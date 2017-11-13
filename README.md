# LDAP server
A simple LDAP server for BUT FIT ISA course.

## Requirements
The server requires **CSV** database file with three columnts separated by semicolons.
- the first colunmn is represented as an attribute **cn** (common name)
- the second column is represented as an attribute **uid** or **userid**
- the third colimn is represented as an atrribude **mail**

You can find an example at *static/example.csv*

## Building

Run `make` from the project root

## Usage

The database file is the only required attribute. Specify it as:
- **-f** $PATH_TO_FILE

You can also specify a port as:
- **-p** $PORT

A default port is 389 - may require superuser privileges

This usage guide can be also printed using a help switch
- **-h**


### Example
`$ ./myldap -f static/example.csv -p 1234`

*ldapsearch* utility may be used for server testing

`$ ldapsearch -x -h localhost -p 1234`

Parameter `-x` must be supplied for client to use simple bind method.

## Supported operations

Client may use following operations

- *bind*
- *searchRequest*
    - *present*: match all entries in the database
        - `""`
    - *equalityMatch*: string match
        - `"uid=psveter"`
    - *substrings*: match substring
        - `"cn=Peter*"`
    - *not*: filter negation
        - `"(!(cn=*er))"`
    - *or*: filter disjunction
        - `"(|(cn=Pet*)(cn=Joz*))"`
    - *and*: filter conjunction
        - `"(&(cn=Pet*)(uid=psv*))"`
    - *unbind*

## Responses

Server provides following responses
- *bindResponse*
- *searchResEntry*
- *searchResDone*

## More info
See `docs/`.
Detailed documentation is available only in Slovak.

## COPYING
See `LICENSE`

## Author
Eduard Čuba <xcubae00@stud.fit.vutbr.cz>

November 2017
