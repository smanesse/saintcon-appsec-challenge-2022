from django.test import TestCase
import os
from taskManager.models import Project, File, Notes, Task, Project, UserProfile
from django.test import Client
from django.contrib.auth.models import User
from django.db.utils import OperationalError


class TestSecurity(TestCase):
    "Security Tests for Django Secure Coding"
    fixtures = ['users', 'usersProfiles', 'groups', 'auth_group_permissions', 'taskManagerProjects', 'taskManagerNotes',
                'taskManagerTasks']

    def setUp(self):
        self.client = Client()

    # def tearDown(self):
    # Nothing todo yet
    def test_sqli_1(self):
        "vtm is vulnerable to SQL Injection (project_details)"

        # Create a project to upload files to
        post_data = {'title': 'sqli test', 'text': 'testing 123', 'project_priority': 1,
                     'project_duedate': '2022-07-13'}
        self.client.login(username="seth", password="soccerlover")
        request = self.client.post("/taskManager/project_create/", post_data)

        vulnerable = False

        # Check if the raw/unsanitized SQL is present
        try:
            self.client.get("/taskManager/1 '/project_details/")
        except OperationalError:
            vulnerable = True

        assert vulnerable != True

    def test_sqli_1_functional(self):
        "vtm is vulnerable to SQL Injection (project_details) but works"

        # Create a project to upload files to
        post_data = {'title': 'sqli test', 'text': 'testing 123', 'project_priority': 1,
                     'project_duedate': '2022-07-13'}
        self.client.login(username="seth", password="soccerlover")
        response = self.client.post("/taskManager/project_create/", post_data)

        id = Project.objects.last().id

        # Check if the raw/unsanitized SQL is present
        response = self.client.get(f"/taskManager/{id}/project_details/")
        assert response.status_code == 200 and b"testing 123" in response.content

    def test_sqli_2(self):
        "vtm is vulnerable to SQL Injection (forgot_password)"
        post_data = {"email": "\'"}

        vulnerable = False

        # Check if the raw/unsanitized SQL is present
        try:
            request = self.client.post("/taskManager/forgot_password/", post_data)
        except OperationalError:
            vulnerable = True

        assert vulnerable != True

    def test_sqli_2_functional(self):
        "vtm isn't vulnerable to SQL Injection (forgot_password) but works"

        post_data = {
            'username': 'test_reset_password',
            'first_name': 'reset',
            'last_name': 'password',
            'email': 'reset_password@example.com',
            'password': 'password123',
        }
        request = self.client.post("/taskManager/register/", post_data)

        post_data = {"email": "reset_password@example.com"}
        request = self.client.post("/taskManager/forgot_password/", post_data)

        user = User.objects.get(email='reset_password@example.com')
        assert len(user.userprofile.reset_token) >= 6

    def test_sqli_3(self):
        "vtm  is vulnerable to SQL Injection (search)"
        query_params = {"q": "a\'"}
        self.client.login(username="seth", password="soccerlover")

        vulnerable = False

        # Check if the raw/unsanitized SQL is present
        try:
            request = self.client.get("/taskManager/search/", {'q': "a\'"})
        except OperationalError:
            vulnerable = True

        assert vulnerable != True

    def test_sqli_3_functional(self):
        "vtm is vulnerable to SQL Injection (search) but works"
        query_params = {"q": "a\'"}
        self.client.login(username="seth", password="soccerlover")

        # Check if the raw/unsanitized SQL is present
        request = self.client.get("/taskManager/search/", {'q': "a"})

        assert request.status_code == 200 and b"No tasks found" in request.content

    def test_xss_1(self):
        "vtm is vulnerable to XSS (hint: search)"
        self.client.login(username="seth", password="soccerlover")
        content = self.client.get("/taskManager/search/", {'q': 'item"<script>alert(1234)</script>'}).content
        vulnerable = (b"<script>alert(1234)</script>" in content)

        assert vulnerable != True

    def test_xss_1_functional(self):
        "vtm is vulnerable to XSS (hint: search) but works"
        self.client.login(username="seth", password="soccerlover")
        content = self.client.get("/taskManager/search/", {'q': '<script'}).content
        assert b"<script" in content

    def test_xss_2(self):
        "vtm is vulnerable to XSS (hint: task_details)"
        # Create an authenticated client
        self.client.login(username="seth", password="soccerlover")

        # Grab the last project so we can add a task to it, later
        project = Project.objects.filter(users_assigned=2)[0]

        task = Task(title='<script>alert(1);</script>', text='oops, xss', due_date='2017-05-30 11:46:19.261784',
                    start_date='2022-05-30 11:46:19.261784', project_id=project.id)
        task.save()

        content = self.client.get("/taskManager/" + str(project.id) + "/" + str(task.id) + "/").content
        vulnerable = (b"<script>alert(1);</script>" in content)

        assert vulnerable != True

    def test_xss_2_functional(self):
        "vtm is vulnerable to XSS (hint: task_details) but works"
        # Create an authenticated client
        self.client.login(username="seth", password="soccerlover")

        # Grab the last project so we can add a task to it, later
        project = Project.objects.filter(users_assigned=2)[0]

        task = Task(title='scripty boi', text='oops, xss', due_date='2017-05-30 11:46:19.261784',
                    start_date='2022-05-30 11:46:19.261784', project_id=project.id)
        task.save()

        content = self.client.get("/taskManager/" + str(project.id) + "/" + str(task.id) + "/").content
        assert b"scripty boi" in content

    def test_username_enum_login(self):
        "vtm is vulnerable to username enumeration (hint: login form)"
        c = Client()
        r1 = c.post("/taskManager/login/", {'username': 'UserDoesNetExst', 'password': 'badpassword'})

        vulnerable = (b"Invalid Username. Please try again" in r1.content)

        assert vulnerable != True

    def test_command_injection(self):
        "vtm is vulnerable to command injection (hint: ping)"
        self.client.login(username='dade', password='hacktheplanet')
        res = self.client.post('/taskManager/ping/', {"ip": "127.0.0.1; ls"})
        vulnerable = (b'manage.py' in res.content)

        assert vulnerable != True

    def test_csrf1(self):
        "vtm is vulnerable to CSRF (hint: profile by id)"
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.login(username="seth", password="soccerlover")
        data = {'first_name': 'Seth', 'last_name': 'Law', 'email': 'seth@tm.com', 'dob': '02/02/82'}
        res = csrf_client.post('/taskManager/profile/2', data)
        vulnerable = (res.status_code == 200)

        assert vulnerable != True

    def test_csrf1_functional(self):
        "vtm is vulnerable to CSRF (hint: profile by id) but works"
        csrf_client = Client(enforce_csrf_checks=False)
        csrf_client.login(username="seth", password="soccerlover")
        data = {'first_name': 'Seth', 'last_name': 'Law', 'email': 'seth@tm.com', 'dob': '02/02/82'}
        res = csrf_client.post('/taskManager/profile/2', data)
        assert res.status_code == 200

    def test_csrf2(self):
        "vtm is vulnerable to CSRF (hint: password change)"
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.login(username="seth", password="soccerlover")
        data = {'new_password': 'soccerlover1', 'confirm_password': 'soccerlover1'}
        res = csrf_client.post('/taskManager/change_password/', data)
        vulnerable = (res.status_code == 200)

        assert vulnerable != True

    def test_csrf2_functional(self):
        "vtm is vulnerable to CSRF (hint: password change) but works"
        csrf_client = Client(enforce_csrf_checks=False)
        csrf_client.login(username="seth", password="soccerlover")
        data = {'new_password': 'soccerlover1', 'confirm_password': 'soccerlover1'}
        res = csrf_client.post('/taskManager/change_password/', data)
        assert res.status_code == 200

    def test_unvalidated_redirect1(self):
        "vtm is vulnerable to Unvalidated Redirects (hint: logout)"
        self.client.login(username='dade', password='hacktheplanet')
        res = self.client.get('/taskManager/logout', {'redirect': 'https://www.google.com'}, follow=True)
        vulnerable = (res.redirect_chain[1][0] == 'https://www.google.com')

        assert vulnerable != True

    def test_unvalidated_redirect2(self):
        "vtm is vulnerable to Unvalidated Redirects (hint:login)"
        data = {'username': 'seth', 'password': 'soccerlover'}
        res = self.client.post('/taskManager/login/?next=https://www.google.com', data, follow=True)
        vulnerable = (res.redirect_chain[0][0] == 'https://www.google.com')

        assert vulnerable != True

    def test_idor_1(self):
        "vtm is vulnerable to Insecure Direct Object Reference (hint:project details)"
        self.client.login(username="chris", password="test123")

        res = self.client.get("/taskManager/2/project_details/").content
        vulnerable = (b"CAKE" in res)

        assert vulnerable != True

    def test_idor_2(self):
        "vtm is vulnerable to Insecure Direct Object Reference (hint:profile details)"
        self.client.login(username="chris", password="test123")
        # try:
        res = self.client.get("/taskManager/profile/2").content
        vulnerable = (b"seth@tm.com" in res)

        assert vulnerable != True

    def test_mass_assign_1(self):
        "vtm is vulnerable to Mass Assignment (superuser)"
        post_data = {
            'username': 'test_mass_assign_9',
            'first_name': 'Mass',
            'last_name': 'Assignment',
            'email': 'mass_assign@vtm.com',
            'password': 'password123',
            'is_superuser': 1
        }
        request = self.client.post("/taskManager/register/", post_data)
        user = User.objects.get(username='test_mass_assign_9')

        assert user.is_superuser != True

    def test_mass_assign_1_functional(self):
        "vtm is vulnerable to Mass Assignment (superuser)"
        post_data = {
            'username': 'test_mass_assign_functional',
            'first_name': 'Mass',
            'last_name': 'Assignment',
            'email': 'mass_assign@vtm.com',
            'password': 'password123',
        }
        request = self.client.post("/taskManager/register/", post_data)
        user = User.objects.get(username='test_mass_assign_functional')

        assert user

    def test_mass_assign_2(self):
        "vtm is vulnerable to Mass Assignment (superuser)"
        post_data = {
            'username': 'test_mass_assign_9',
            'first_name': 'Mass',
            'last_name': 'Assignment',
            'email': 'mass_assign@vtm.com',
            'password': 'password123',
            'is_staff': 1
        }
        request = self.client.post("/taskManager/register/", post_data)
        user = User.objects.get(username='test_mass_assign_9')

        assert user.is_staff != True

    def test_mass_assign_2_functional(self):
        "vtm is vulnerable to Mass Assignment (superuser)"
        post_data = {
            'username': 'test_mass_assign_2_functional',
            'first_name': 'Mass',
            'last_name': 'Assignment',
            'email': 'mass_assign@vtm.com',
            'password': 'password123',
        }
        request = self.client.post("/taskManager/register/", post_data)
        user = User.objects.get(username='test_mass_assign_2_functional')

        assert user
