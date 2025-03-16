## The Ultimate curl Manual: Conquer the Command Line

`curl` is the command-line Swiss Army knife for transferring data with URLs. From simple web page retrieval to complex API interactions, `curl` empowers you to manipulate HTTP requests and responses with unparalleled precision. This manual dives deep into `curl`'s capabilities, equipping you with the knowledge to conquer any web challenge.

**I. Core Concepts:**

- **URL:** The Uniform Resource Locator specifies the resource you want to interact with (e.g., `http://example.com/page.html`).
- **HTTP Methods:** Define the action to be performed on the resource (GET, POST, PUT, DELETE, HEAD, OPTIONS, etc.).
- **Headers:** Key-value pairs that provide additional information about the request or response (e.g., `Content-Type`, `User-Agent`).
- **Data:** The content sent with the request (for POST, PUT, etc.).
- **Response:** The server's reply to the request, including status codes (e.g., 200 OK, 404 Not Found) and data.

**II. Basic Usage:**

1. **Retrieving a Web Page:**
    
    Bash
    
    ```
    curl http://example.com
    ```
    
    This performs a GET request and displays the HTML content of the page.
    
2. **Saving the Output:**
    
    Bash
    
    ```
    curl -o output.html http://example.com
    ```
    
    Saves the output to `output.html`. `-O` saves with the filename from the URL.
    
3. **Following Redirects:**
    
    Bash
    
    ```
    curl -L http://example.com/shortlink
    ```
    
    Follows HTTP redirects (301, 302, etc.) to the final destination.
    
4. **Verbose Output:**
    
    Bash
    
    ```
    curl -v http://example.com
    ```
    
    Displays detailed information about the request and response, including headers. Essential for debugging.
    

**III. HTTP Methods:**

1. **POST Request:**
    
    Bash
    
    ```
    curl -X POST -d "name=John&age=30" http://example.com/submit
    ```
    
    Sends data using the POST method. `-d` specifies the data.
    
2. **POST with JSON Data:**
    
    Bash
    
    ```
    curl -X POST -H "Content-Type: application/json" -d '{"name": "John", "age": 30}' http://example.com/api
    ```
    
    Sends JSON data. `-H` sets the `Content-Type` header.
    
3. **PUT Request:**
    
    Bash
    
    ```
    curl -X PUT -d "data=updated" http://example.com/resource/1
    ```
    
    Updates a resource.
    
4. **DELETE Request:**
    
    Bash
    
    ```
    curl -X DELETE http://example.com/resource/1
    ```
    
    Deletes a resource.
    
5. **HEAD Request:**
    
    Bash
    
    ```
    curl -I http://example.com
    ```
    
    Retrieves only the headers of the response, useful for checking server status or file modification times.
    

**IV. Headers:**

6. **Custom Headers:**
    
    Bash
    
    ```
    curl -H "X-Custom-Header: value" http://example.com
    ```
    
    Adds a custom header to the request.
    
7. **User-Agent:**
    
    Bash
    
    ```
    curl -H "User-Agent: My-Awesome-Script" http://example.com
    ```
    
    Sets the User-Agent header, which identifies the client making the request.
    
8. **Referer:**
    
    Bash
    
    ```
    curl -H "Referer: http://previous.page.com" http://example.com
    ```
    
    Sets the Referer header, indicating the previous page the user came from.
    

**V. Data and Parameters:**

9. **URL Encoding:**
    
    Bash
    
    ```
    curl --data-urlencode "param1=value with spaces&param2=another value" http://example.com/submit
    ```
    
    URL-encodes the data, which is essential for including special characters in URLs.
    
10. **Sending Files:**
    
    Bash
    
    ```
    curl -F "file=@/path/to/file.txt" http://example.com/upload
    ```
    
    Uploads a file using multipart/form-data encoding.
    
11. **Reading Data from a File:**
    
    Bash
    
    ```
    curl -d "@data.txt" http://example.com/submit
    ```
    
    Sends the contents of `data.txt` as the request body.
    

**VI. Authentication:**

12. **Basic Authentication:**
    
    Bash
    
    ```
    curl -u user:password http://example.com
    ```
    
    Uses basic authentication.
    
13. **Digest Authentication:**
    
    Bash
    
    ```
    curl --digest -u user:password http://example.com
    ```
    
    Uses digest authentication.
    

**VII. Cookies:**

14. **Sending Cookies:**
    
    Bash
    
    ```
    curl -b cookies.txt http://example.com
    ```
    
    Sends cookies from the `cookies.txt` file.
    
15. **Saving Cookies:**
    
    Bash
    
    ```
    curl -c cookies.txt http://example.com
    ```
    
    Saves cookies to the `cookies.txt` file.
    

**VIII. Proxies:**

16. **Using a Proxy:**
    
    Bash
    
    ```
    curl --proxy http://proxy.example.com:8080 http://example.com
    ```
    
    Uses the specified HTTP proxy.
    

**IX. Other Useful Options:**

17. **Timeout:**
    
    Bash
    
    ```
    curl --connect-timeout 5 http://example.com
    ```
    
    Sets a timeout for the connection.
    
18. **Max Redirections:**
    
    Bash
    
    ```
    curl --max-redirs 3 http://example.com
    ```
    
    Limits the number of redirects to follow.
    
19. **Range:**
    
    Bash
    
    ```
    curl -r 0-1023 http://example.com/largefile.zip
    ```
    
    Retrieves a specific range of bytes from a file.
    
20. **Headless Browsing (with rendering engine):**
    
    Bash
    
    ```
    curl --render-html http://example.com
    ```
    
    Renders the HTML content, useful for JavaScript execution.
    

**X. Examples for CTFs:**

21. **Enumerating Subdomains (using a wordlist):**
    
    Bash
    
    ```
    for subdomain in $(cat subdomains.txt); do
        curl http://$subdomain.example.com 2>/dev/null | grep "Something interesting"
    done
    ```
    
22. **Checking for HTTP methods:**
    
    Bash
    
    ```
    curl -X OPTIONS http://example.com
    ```
    
23. **Interacting with APIs:**
    
    Bash
    
    ```
    curl -X POST -H "Content-Type: application/json" -d '{"key": "value"}' http://example.com/api/endpoint
    ```
    
24. **Bypassing basic authentication (if vulnerable):**
    
    Bash
    
    ```
    curl -u admin:incorrect_password http://example.com/admin  # Check for error messages
    ```
    

**XI. Conclusion:**

`curl` is an incredibly versatile tool. Mastering its many options will significantly enhance your ability to interact with web services and solve web-based CTF challenges. This manual provides a comprehensive overview of `curl`'s capabilities, but the best way to learn is through practice. Experiment with different options and explore the `curl` man page (`man curl`) for even more advanced techniques. Happy curling!