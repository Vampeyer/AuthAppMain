

This is an authentication application 
built using Grok , HTML , CSS , and JS - 
with a subscription option via stripe 
to the content in the - " subscriptions "
folder. 

Built for StreamPal-v2

===========================================================
- To use this repository - 
=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-=-=-=-=-=-=
* Locally
--------------------------------------------------
#1 - Creating Database - use the Create Table DB .txt to enter into a
 myphp panel or a mySQL server , 
to create the table used in this project. 

So , go into a hosting service or use XAMPP , and spin one up. 
you will be able to see the admin panel at localhost/phpmyadmin , when 
it is turned on.  if you change the port , enter the port to visit 
i.e. localhost:81/phpmyadmin 

#2 - 
Fill out the following in a .env file 
with your mySQL server data , to connnect. 

MYSQL_HOST=
MYSQL_USER=
MYSQL_PASSWORD=
MYSQL_DATABASE=
MYSQL_PORT=


#3 
in the server.js , 

on lines  20 - 22 , change the  

const PRICE_WEEKLY = 'price_XXXXXX'; // 7 days for $2.95
const PRICE_MONTHLY = 'price_XXXXX'; // 30 days for $7.75


# 4 , start the mySQL server , you may fill in your info 

# 5 , install npm modules and start the server
  ( In a terminal or cmmand prompt in the directory , type -  )
 
 - npm install 
 - npm run dev  - to local test. 

 -----------------------------------------------

 # Production ,  
#1 - Creating Database - use the Create Table DB .txt to enter into a
 myphp panel or a mySQL server , 

 - on your selected hosting service , or open ports for self hosting , 
 and use MySQL to 
to create a database the table used in this project. 


So , go into a hosting service that has a MySQL db with it. 
and it should be running , giving you info for the .env file. 

#2 - 
Fill out the following in a .env file 
with your mySQL server data - from your MySQL database 
 , to connnect. 

MYSQL_HOST=
MYSQL_USER=
MYSQL_PASSWORD=
MYSQL_DATABASE=
MYSQL_PORT=


#3 
in the server.js , 

on lines  20 - 22 , change the  price , and update it with your correct 
price from stripe. 

const PRICE_WEEKLY = 'price_XXXXXX'; // 7 days for $2.95
const PRICE_MONTHLY = 'price_XXXXX'; // 30 days for $7.75


# 4 

( to test the db online locally before moving on  )
# 5 , install npm modules and start the server
  ( In a terminal or cmmand prompt in the directory , type -  )
 
 - npm install 
 - npm run dev  - to local test. 

const DOMAIN = process.env.NODE_ENV === 'production' ? '- www. insert production url here - .com' : 'http://localhost:3000';

                                       change production url               

6 , - Your production URL is where your server is being hosted from , 
now , we must do that to get that , find a hosting service , like render , 
and host the server.js file , that should connect too your database. 

 -  you may check your connection too your database with the test_db.js file 
 along the way , to ensure you have the correct logins. 

 
 #7 , be sure to update the secret key , webhook key , 
 the production URL and prices when switching 
 from local to production. 