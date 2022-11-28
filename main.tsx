/** @jsx h */

import blog, { ga, redirects, h } from "blog";

blog({
  title: "HexF",
  author: "Thomas Hobson",
  links: [
    {title: "GitHub", url: "https://github.com/HexF"},
    {title: "Email", url:"mailto:website@hexf.me"}
  ],
  lang: "en",

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
