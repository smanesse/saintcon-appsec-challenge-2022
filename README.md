# SAINTCON AppSec Challenge Repository

## Task Manager

To run locally:
----
1. ```python3 -m venv venv```
2. ```source venv/bin/activate```
3. ```pip install -r requirements.txt```
4. ```./manage.py migrate```
5. ```./manage.py loaddata taskManager/fixtures/*```
6. ```./manage.py runserver```
7. Navigate to http://localhost:8000
8. Login with the username `chris` and a password of `test123`


To run tests:
----
1. ```Follow above instructions to get everything installed correctly```
2. From the top directory, run ```./manage.py test```
