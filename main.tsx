/** @jsx h */

import blog, { ga, redirects, h } from "blog"
import "https://esm.sh/prismjs@1.29.0/components/prism-markup-templating";
import "https://esm.sh/prismjs@1.29.0/components/prism-python";
import "https://esm.sh/prismjs@1.29.0/components/prism-php";

blog({
  title: "HexF",
  author: "Thomas Hobson",
  links: [
    {title: "GitHub", url: "https://github.com/HexF"},
    {title: "Email", url:"mailto:website@hexf.me"}
  ],
  lang: "en",
  disableHtmlSanitization: true

  // middlewares: [

    // If you want to set up Google Analytics, paste your GA key here.
    // ga("UA-XXXXXXXX-X"),

    // If you want to provide some redirections, you can specify them here,
    // pathname specified in a key will redirect to pathname in the value.
    // redirects({
    //  "/hello_world.html": "/hello_world",
    // }),

  // ]
});
