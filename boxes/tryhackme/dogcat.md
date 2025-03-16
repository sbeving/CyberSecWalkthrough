# dogcat

### dogcat Machine - Path Traversal & LFI to Flag



**Introduction:**

The "dogcat" machine presents a web application vulnerable to path traversal and Local File Inclusion (LFI). The application uses a `view` parameter in its URL to include different files based on the user's selection. By exploiting these vulnerabilities, we can bypass the intended application flow, read the content of arbitrary files, and ultimately obtain the flag.

**Vulnerability Analysis:**

1.  **Path Traversal:**

    * The application's `index.php` script uses the `view` parameter from the URL to determine which file to include.
    * The script uses PHP's `include()` function. This function attempts to load and execute a PHP file.
    * The application doesn't properly sanitize the `view` parameter before using it. The vulnerable code looks something like this:

    ```php
    <?php
      $view = $_GET['view'];
      include($view . '.php');
    ?>
    ```

    * As a result, it's possible to use path traversal sequences like `../` to navigate outside of the intended directory and access other files.
2. **Local File Inclusion (LFI):**
   * The application has a directory structure that includes, at the minimum:
     * `index.php`: The main application script.
     * `dogs/` directory
     * `cats/` directory.
     * `flag.php`: A file located at the web root containing the flag.
   * By exploiting the path traversal vulnerability, an attacker can control the value passed to `include()` function and include a file outside of the application's intended directories, leading to LFI.
   * Since PHP executes the included file, we can use PHP wrappers to manipulate the content of the file.

**Exploitation Steps:**

1. **Initial Discovery:**
   * The application presents a basic interface with buttons to view "dog" or "cat" images. This hints at the `view` parameter.
   * Initial attempts to use path traversal like `/?view=cats/../index` resulted in "file not found" errors and path traversal did not work as expected.
2. **Understanding the application logic:**
   * By analyzing the php errors, it was understood that the value of the `view` parameter was directly being used with an `include()` function. The initial thought that the `view` parameter should start with `cat` or `dog` was incorrect.
3. **Exploiting Path Traversal:**
   * Since there are directories like `dogs` and `cats` present, a relative path starting with either of those directory name must exist.
   * The presence of the `flag.php` in the root directory was not known initially.
   * The approach to traverse up to the root directory and access the `flag.php` file was taken.
   * We determined that the `flag.php` file is located at the root level, next to the `index.php` file.
   * To access this file, we use `dogs/../flag` to traverse one directory up from the `dogs` directory.
4. **Using `php://filter` for Content Leakage:**
   * Since the server is not displaying the content of `flag.php`, we will use php wrapper `php://filter` to examine the content of flag.php.
   *   The vulnerable `view` parameter was modified to utilize the `php://filter` wrapper, specifically using `convert.base64-encode` to encode the `flag.php` content into Base64:

       ```
       http://10.10.188.94/index.php?view=php://filter/convert.base64-encode/resource=dogs/../flag
       ```
5. **Analyzing the Response:**
   * The server's response contained the Base64 encoded contents of `flag.php`. Decoding the Base64 data revealed the flag.

**Working Payload:**

```
http://10.10.188.94/index.php?view=php://filter/convert.base64-encode/resource=dogs/../flag
```



<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>



**Flag:**

```
THM{Th1s_1s_N0t_4_Catdog_ab67edfa}
```

**Mitigation:**

1. **Input Validation/Sanitization:** Always validate and sanitize user inputs to prevent path traversal. A whitelist approach should be preferred over blacklist approach.
2. **Avoid Direct `include` on User Input:** Use a templating system, or map user-controlled parameters to specific file paths that you control. Do not directly use user input within the `include()` function.
3. **Least Privilege:** Ensure the web server process has only the necessary permissions to operate, limiting access to sensitive files.
4. **Regular Security Audits:** Conduct regular security audits and penetration testing to identify and remediate vulnerabilities promptly.

<pre class="language-php"><code class="lang-php"><strong>// /var/www/html/index.php
</strong><strong>&#x3C;!DOCTYPE HTML>
</strong>&#x3C;html>

&#x3C;head>
   &#x3C;title>dogcat&#x3C;/title>
   &#x3C;link rel="stylesheet" type="text/css" href="/style.css">
&#x3C;/head>

&#x3C;body>
   &#x3C;h1>dogcat&#x3C;/h1>
   &#x3C;i>a gallery of various dogs or cats&#x3C;/i>

   &#x3C;div>
       &#x3C;h2>What would you like to see?&#x3C;/h2>
       &#x3C;a href="/?view=dog">&#x3C;button id="dog">A dog&#x3C;/button>&#x3C;/a> &#x3C;a href="/?view=cat">&#x3C;button id="cat">A cat&#x3C;/button>&#x3C;/a>&#x3C;br>
       &#x3C;?php
           function containsStr($str, $substr) {
               return strpos($str, $substr) !== false;
           }
       $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
           if(isset($_GET['view'])) {
               if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                   echo 'Here you go!';
                   include $_GET['view'] . $ext;
               } else {
                   echo 'Sorry, only dogs or cats are allowed.';
               }
           }
       ?>
   &#x3C;/div>
&#x3C;/body>

&#x3C;/html>
</code></pre>





**Conclusion:**

The "dogcat" machine demonstrates the dangers of path traversal and LFI vulnerabilities. By exploiting the `view` parameter, we were able to bypass the application's intended flow, read the contents of arbitrary files, and extract the flag. Proper input sanitization, careful file handling, and regular security audits are crucial for preventing these vulnerabilities.
