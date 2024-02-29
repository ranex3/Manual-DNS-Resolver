# Description
A manual implementation of a DNS resolver.

# How to run

To start the resolver, run the following command:
```
python resolver.py 5200 10
```
This will start the resolver on port 5200, and will timeout if no results are found after 10 seconds after a query is made.

Example queries:
```
python client.py 127.0.0.1 5200 www.google.com 5
```
```
python client.py 127.0.0.1 5200 www.example.com 5
```
These commands will find answers to A queries for www.google.com and www.example.com, and timeout if no
results are found after 5 seconds.
