CS 5700 - Network Fundamentals
Project 2: Web Crawler
https://david.choffnes.com/classes/cs4700fa20/project2.php
Xinyu Ye and Jeff Taylor

This program crawls a "fakebook" site created by the course staff looking for secret flags that are embedded in some pages.  The secret flags appear in the following format in the html:```html<h2 class='secret_flag' style="color:red"> FLAG: 64-characters-of-random-alphanumerics</h2>.```The program ends when all 5 flags are found, or all the pages have been visted, whichever comes first.

High Level Approach:

- Establish connection with the server
- Login to fakebook using the username and password provided to us by the course staff
- While loop that runs while number of flags found is less than 5 and there are still unvisited pages
	- Scan the friends list (urls) on the page, adding any unvisited urls to the frontier of pages still to visit
	- Scan the content of the page for flags and keeping track of any found flags

Challenges:

-Reverse engineering the login
-Determining most efficient way to parse
-Thinking about the most efficient data structures for Frontier and Visited


Testing:

-Individual method testing with debug statements
	- Initially we used debug statements to visualize the status codes and content being returned by the get(url) method.
	- We could watch the program run, seeing what was being sent, received, and what was being added to Visited and 	   Frontier  
End to End Testing: Ran the program many times on the server and validated that 5 secret key were returned as the only output

What we eached worked on (by who was the author of each function):

Xinyu Ye:
	- connection()
	- send(message)
	- login(username, password)
	- get(url)
	- parse_response(resp)
	- set_cookie(headers)

Jeff Taylor:
	- handle_response(status, headers, content)
	- add_unvisited_profiles_to_frontier(html)
	- scan_for_secret_flags(html)
	- main (with review and improvements from Xinyu)

