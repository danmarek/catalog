# Project Name: Item Catalog
This project creates an Item Catalog application used to store tv shows on the three major networks using a **postgres** database.

The project uses google signin for authorization, allows a logged in user to add, edit and delete items and provides a JSON read only endpoint for the catalog.

The **application.py** uses several libraries including **flask** web framework, **sqlalchemy** for orm database support and **oauth2client**.


A future enhancement is planned to allow creation of additional channel categories and add a "watch" counter on a show item to track the number of times a show is watched.

# Deployment Information
Application can be deployed on an apache web server running postgresql, python-psycopg2, libpq-dev, git and using wsgi libapache2-mod-wsgi-py3 to run a python web application built in flask.

**requirements.txt** contains the python libraries used by this application. 

Your README.md file should include all of the following:
i. The IP address and SSH port so your server can be accessed by the reviewer.
ii. The complete URL to your hosted web application.
iii. A summary of software you installed and configuration changes made.
iv. A list of any third-party resources you made use of to complete this project.

### Server IP and SSH port
100.24.174.199 using port 22

### complete URL to your hosted web application.
http://100.24.174.199.xip.io/

### Summary of software installed
- apache2
- libapache2-mod-wsgi-py3
- postgresql
- python-psycopg2
- libpq-dev
- git
- python3
- **requirements.txt** contains the python libraries used by this application. 

### Configuration changes
- secured server to use ssh key
- enabled firewall for ssh and http
- Created a postgresql catalog role and database
- Updated postgresql configuration using md5 
- Configured apache default.conf to run the wsgi python application

### Third Party Resources
- Google API authentication
- Postgresql
- Apache

# Author
Cheers
Dan Marek
