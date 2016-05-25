
###Now horribly outdated! This may still work, but your mileage will vary a lot.###


BurpJS
=============

BurpJS is an extension to the [Burp Suite](http://portswigger.net/burp/) that allows scripting Burp with JavaScript.


Features
--------

* Automatic reload. Make changes to your JavaScript source files and the changes are loaded on the next HTTP message through Burp.
* Integrated debugger. Step debug your JavaScript, or use the debugger to eval JavaScript allowing you to pause and modify requests/responses as they pass through Burp.
* Access the all Java libraries. The JavaScript engine is [Rhino](https://www.mozilla.org/rhino/), so you have full access to any Java library you like, just add it to the classpath.


Use
---

The main.js file contains two main methods, processRequest and processResponse. This is where you want to put your code. These are called each time a 
request passes through (or is generated by) Burp. The toolName parameter is a string corresponding to the where the request came from, ie proxy, 
repeater etc. The other parameters requestMessage and responseMessage are mutable objects that essentially wrap a byte array representing the HTTP 
message. Check out the javadocs for the HttpMessage class for methods available.

Any changes you make to any file in the javascript directory is automatically reloaded on the next HTTP message burp processes. Any file ending in .js in the
javascript directory is loaded into the JavaScript context and monitored for changes. However, if you add a new file the extension doesn't know about then you'll have to restart burp, otherwise it will
be ignored.

The Rhino JavaScript debugger is opened by right clicking in Burp and selected "Open JS Debugger". If you don't see that option, try right clicking on a proxy
history entry, Burp doesn't have the best menu integration. The debugger will reload the JavaScript files and break on interpreting them, so everything will stop
until you hit Go. Each source file will open in a internal window but they normally overlap, so you have to minimise each window until you can see which file you
want to debug.

The library.js file is worth checking out, it contains various useful functions and is a good place to add anything you think should be core functionality.
I'm interested in any code you write to work with BurpJS, so feel free to email me (<aj@shinynightmares.com>) a diff or anything you want to contribute.



Install
-------

Go to [shinynightmares.com](http://shinynightmares.com) and grab the binary zip. Extract it to your Burp install directory and start burp with the provided batch/bash script, you'll see some notices in the console and in Burps
alert tab if everything went to plan. You'll probably have to edit the bash/batch file for the correct version of burp you're using.



