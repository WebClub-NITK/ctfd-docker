import traceback
import docker as docker_lib

from CTFd.plugins.challenges import BaseChallenge, CHALLENGE_CLASSES, get_chal_class
from CTFd.plugins.flags import get_flag_class
from CTFd.utils.user import get_ip
from CTFd.utils.uploads import delete_file
from CTFd.plugins import register_plugin_assets_directory, bypass_csrf_protection
from CTFd.schemas.tags import TagSchema
from CTFd.models import db, ma, Challenges, Teams, Users, Solves, Fails, Flags, Files, Hints, Tags, ChallengeFiles
from CTFd.utils.decorators import admins_only, authed_only, during_ctf_time_only, require_verified_emails
from CTFd.utils.decorators.visibility import check_challenge_visibility, check_score_visibility
from CTFd.utils.user import get_current_team
from CTFd.utils.user import get_current_user
from CTFd.utils.user import is_admin, authed
from CTFd.utils.config import is_teams_mode
from CTFd.api import CTFd_API_v1
from CTFd.api.v1.scoreboard import ScoreboardDetail
import CTFd.utils.scores
from CTFd.api.v1.challenges import ChallengeList, Challenge
from flask_restx import Namespace, Resource
from flask import request, Blueprint, jsonify, abort, render_template, url_for, redirect, session
# from flask_wtf import FlaskForm
from wtforms import (
    FileField,
    HiddenField,
    PasswordField,
    RadioField,
    SelectField,
    StringField,
    TextAreaField,
    SelectMultipleField,
    BooleanField,
)
# from wtforms import TextField, SubmitField, BooleanField, HiddenField, FileField, SelectMultipleField
from wtforms.validators import DataRequired, ValidationError, InputRequired
from werkzeug.utils import secure_filename
# import requests
import tempfile
from CTFd.utils.dates import unix_time
from datetime import datetime
import json
import hashlib
import random
from CTFd.plugins import register_admin_plugin_menu_bar
import string
from CTFd.forms import BaseForm
from CTFd.forms.fields import SubmitField
from CTFd.utils.config import get_themes


class DockerConfig(db.Model):
    """
	Docker Config Model. This model stores the config for docker API connections.
	"""
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column("hostname", db.String(64), index=True)
    tls_enabled = db.Column("tls_enabled", db.Boolean, default=False, index=True)
    ca_cert = db.Column("ca_cert", db.String(2200), index=True)
    client_cert = db.Column("client_cert", db.String(2000), index=True)
    client_key = db.Column("client_key", db.String(3300), index=True)
    repositories = db.Column("repositories", db.String(1024), index=True)


class DockerChallengeTracker(db.Model):
    """
	Docker Container Tracker. This model stores the users/teams active docker containers.
	"""
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column("team_id", db.String(64), index=True)
    user_id = db.Column("user_id", db.String(64), index=True)
    docker_image = db.Column("docker_image", db.String(64), index=True)
    timestamp = db.Column("timestamp", db.Integer, index=True)
    revert_time = db.Column("revert_time", db.Integer, index=True)
    instance_id = db.Column("instance_id", db.String(128), index=True)
    ports = db.Column('ports', db.String(128), index=True)
    host = db.Column('host', db.String(128), index=True)


class DockerConfigForm(BaseForm):
    id = HiddenField()
    hostname = StringField(
        "Docker Hostname", description="The Hostname/IP and Port of your Docker Server"
    )
    tls_enabled = RadioField('TLS Enabled?')
    ca_cert = FileField('CA Cert')
    client_cert = FileField('Client Cert')
    client_key = FileField('Client Key')
    repositories = SelectMultipleField('Repositories')
    submit = SubmitField('Submit')


def define_docker_admin(app):
    admin_docker_config = Blueprint('admin_docker_config', __name__, template_folder='templates',
                                    static_folder='assets')

    @admin_docker_config.route("/admin/docker_config", methods=["GET", "POST"])
    @admins_only
    def docker_config():
        docker = DockerConfig.query.filter_by(id=1).first()
        form = DockerConfigForm()
        if request.method == "POST":
            if docker:
                b = docker
            else:
                b = DockerConfig()
            try:
                ca_cert = request.files['ca_cert'].stream.read()
            except FileNotFoundError:
                app.logger.error("CA Cert file not found")
                print(traceback.print_exc())
                ca_cert = b''
            try:
                client_cert = request.files['client_cert'].stream.read()
            except:
                print(traceback.print_exc())
                client_cert = ''
            try:
                client_key = request.files['client_key'].stream.read()
            except:
                print(traceback.print_exc())
                client_key = ''
            if len(ca_cert) != 0: b.ca_cert = ca_cert
            if len(client_cert) != 0: b.client_cert = client_cert
            if len(client_key) != 0: b.client_key = client_key
            b.hostname = request.form['hostname']
            b.tls_enabled = request.form['tls_enabled']
            if b.tls_enabled == "True":
                b.tls_enabled = True
            else:
                b.tls_enabled = False
            if not b.tls_enabled:
                b.ca_cert = None
                b.client_cert = None
                b.client_key = None
            try:
                b.repositories = ','.join(request.form.to_dict(flat=False)['repositories'])
            except:
                print(traceback.print_exc())
                b.repositories = None
            db.session.add(b)
            db.session.commit()
            docker = DockerConfig.query.filter_by(id=1).first()
        try:
            repos = get_repositories(docker)
        except:
            print(traceback.print_exc())
            repos = list()
        if len(repos) == 0:
            form.repositories.choices = [("ERROR", "Failed to Connect to Docker")]
        else:
            form.repositories.choices = [(d, d) for d in repos]
        dconfig = DockerConfig.query.first()
        try:
            selected_repos = dconfig.repositories
            if selected_repos == None:
                selected_repos = list()
        except:
            print(traceback.print_exc())
            selected_repos = []
        return render_template("docker_config.html", config=dconfig, form=form, repos=selected_repos)

    app.register_blueprint(admin_docker_config)



def define_docker_status(app):
    admin_docker_status = Blueprint('admin_docker_status', __name__, template_folder='templates',
                                    static_folder='assets')

    @admin_docker_status.route("/admin/docker_status", methods=["GET", "POST"])
    @admins_only
    def docker_admin():
        docker_config = DockerConfig.query.filter_by(id=1).first()
        docker_tracker = DockerChallengeTracker.query.all()
        for i in docker_tracker:
            if is_teams_mode():
                name = Teams.query.filter_by(id=i.team_id).first()
                i.team_id = name.name
            else:
                name = Users.query.filter_by(id=i.user_id).first()
                i.user_id = name.name
        
        # Now Docker SDK part for the docker containers
        client = docker_lib.DockerClient(base_url=docker_config.hostname)
        container_info = []
        for container in docker_tracker:
            try:
                container_obj = client.containers.get(container.instance_id)
                container_info.append({
                    'id': container.id,
                    'team_id': container.team_id,
                    'user_id': container.user_id,
                    'docker_image': container.docker_image,
                    'status': container_obj.status,
                    'created_at': container_obj.attrs['Created'],
                    'ports': container_obj.attrs['HostConfig']['PortBindings'],
                    'host': container_obj.attrs['NetworkSettings']['IPAddress']
                })
            except docker_lib.errors.NotFound:
                # Handle case where container is not found
                print("Docker Container not found!")
            except Exception as e:
                print("Error:", e)
                traceback.print_exc()
        
        return render_template("admin_docker_status.html", dockers=container_info)

    app.register_blueprint(admin_docker_status)



kill_container = Namespace("nuke", description='Endpoint to nuke containers')


@kill_container.route("", methods=['POST', 'GET'])
class KillContainerAPI(Resource):
    def get(self):
        docker_config = DockerConfig.query.filter_by(id=1).first()
        client = docker_lib.DockerClient(base_url=docker_config.hostname)
        try:
            container_id = request.args.get('container')
            delete_all = request.args.get('all')

            if delete_all == "true":
                # Delete all containers
                for container in client.containers.list():
                    container.stop()
                    container.remove()
                return {"message": "All containers successfully nuked"}, 200

            elif container_id:
                # Delete a specific container by ID
                container = client.containers.get(container_id)
                container.stop()
                container.remove()
                return {"message": f"Container {container_id} successfully nuked"}, 200
            else:
                return {"message": "No container ID provided"}, 400

        except docker_lib.errors.APIError as e:
            return {"message": f"Failed to nuke containers: {str(e)}"}, 500


def execute_container_command(container_id, command):
    """
    Execute a command in a running container.
    """
    docker_config = DockerConfig.query.filter_by(id=1).first()
    client = docker_lib.DockerClient(base_url=docker_config.hostname)
    try:
        # Find the container by ID
        container = client.containers.get(container_id)
        # Execute the command inside the container
        exec_result = container.exec_run(command)
        return exec_result.output.decode('utf-8')
    except Exception as e:
        print("Execution failed:", e)
        # Log the traceback for debugging purposes
        traceback.print_exc()
        # Return None or any other meaningful response
        return None

def get_client_cert(docker):
    """
    Get the client certificate for TLS configuration.
    """
    tls_enabled = docker.tls_enabled
    ca_cert = docker.ca_cert
    client_cert = docker.client_cert
    client_key = docker.client_key

    if tls_enabled:
        # If TLS is enabled, return the paths to the CA certificate, client certificate, and client key
        return (ca_cert, client_cert, client_key)
    else:
        # If TLS is not enabled, return None
        return None

# For the Docker Config Page. Gets the Current Repositories available on the Docker Server.
def get_repositories(docker, tags=False):
    """
    Get a list of repositories (image names) from the Docker registry.
    """

    tls = docker.tls_enabled
    prefix = 'https' if tls else 'http'
    hostname = docker.hostname
    URL_TEMPLATE = '%s://%s' % (prefix, hostname)

    print("HIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII YOUR hostname IS : ",hostname)

    docker_config = DockerConfig.query.filter_by(hostname=hostname).first()
    print("HIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII YOUR DOCKE CONFIG IS : ",docker_config)
    print('YOUR URL TEMPLATE NOW IS, UMMM : ', URL_TEMPLATE)
    # client = docker_lib.DockerClient(base_url=URL_TEMPLATE)
    docker_host = 'http://host.docker.internal:2375'

    client = docker_lib.DockerClient(base_url=docker_host)
    print("DONEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")
    try:
        # List all images
        images = client.images.list()
        print(images)

        repositories = set()
        for image in images:
            # Get the image tags
            image_tags = image.tags
            if image_tags:
                # Extract the repository name from the image tag
                repository = image_tags[0].split(':')[0]
                repositories.add(repository)
        return list(repositories)
    except Exception as e:
        print("Failed to retrieve repositories:", e)
        # Log the traceback for debugging purposes
        traceback.print_exc()
        return None



def get_unavailable_ports(docker):
    """
    Get a list of ports that are currently in use by containers.
    """
    docker_config = DockerConfig.query.filter_by(id=1).first()
    client = docker_lib.DockerClient(base_url=docker_config.hostname)
    try:
        # List all containers
        containers = client.containers.list()

        unavailable_ports = set()
        for container in containers:
            # Get the container's port bindings
            port_bindings = container.attrs['HostConfig']['PortBindings']
            if port_bindings:
                for binding in port_bindings.values():
                    if binding:
                        # Extract the public port from the binding
                        port = binding[0]['HostPort']
                        unavailable_ports.add(port)
        return list(unavailable_ports)
    except Exception as e:
        print("Failed to retrieve unavailable ports:", e)
        # Log the traceback for debugging purposes
        traceback.print_exc()
        return None

def get_required_ports(docker, image):
    """
    Get the list of ports required by an image.
    """
    docker_config = DockerConfig.query.filter_by(id=1).first()
    client = docker_lib.DockerClient(base_url=docker_config.hostname)
    try:
        # Inspect the image to get its configuration
        image_info = client.images.get(image)
        config = image_info.attrs['Config']
        exposed_ports = config['ExposedPorts']
        return list(exposed_ports.keys())
    except Exception as e:
        print("Failed to retrieve required ports:", e)
        # Log the traceback for debugging purposes
        traceback.print_exc()
        return None

def create_container(docker, image, team, portbl):
    """
    Create a container based on the specified image.
    """
    docker_config = DockerConfig.query.filter_by(id=1).first()
    client = docker_lib.DockerClient(base_url=docker_config.hostname)
    try:
        # Create a container with the specified image
        container = client.containers.create(image, detach=True)

        # Start the container
        container.start()

        # Get the container's port bindings
        port_bindings = container.attrs['HostConfig']['PortBindings']
        ports = [binding[0]['HostPort'] for binding in port_bindings.values() if binding]

        # Extract the container's ID
        container_id = container.id

        return container_id, ports
    except Exception as e:
        print("Failed to create container:", e)
        # Log the traceback for debugging purposes
        traceback.print_exc()
        return None, None



def delete_container(docker, container_id):
    """
    Delete a container by its ID.
    """
    docker_config = DockerConfig.query.filter_by(id=1).first()
    client = docker_lib.DockerClient(base_url=docker_config.hostname)
    try:
        # Get the container object
        container = client.containers.get(container_id)

        # Stop the container if it's running
        if container.status == 'running':
            container.stop()

        # Remove the container
        container.remove()

        return True
    except Exception as e:
        print("Failed to delete container:", e)
        # Log the traceback for debugging purposes
        traceback.print_exc()
        return False



class DockerChallengeType(BaseChallenge):
    id = "docker"
    name = "docker"
    templates = {
        'create': '/plugins/docker_challenges/assets/create.html',
        'update': '/plugins/docker_challenges/assets/update.html',
        'view': '/plugins/docker_challenges/assets/view.html',
    }
    scripts = {
        'create': '/plugins/docker_challenges/assets/create.js',
        'update': '/plugins/docker_challenges/assets/update.js',
        'view': '/plugins/docker_challenges/assets/view.js',
    }
    route = '/plugins/docker_challenges/assets'
    blueprint = Blueprint('docker_challenges', __name__, template_folder='templates', static_folder='assets')
    
    @staticmethod
    def update(challenge, request):
        """
        Update the information associated with a Docker challenge.
        """
        data = request.form or request.get_json()
        for attr, value in data.items():
            setattr(challenge, attr, value)
        db.session.commit()
        return challenge

    @staticmethod
    def delete(challenge):
        """
        Delete a Docker challenge.
        """
        DockerChallenge.query.filter_by(id=challenge.id).delete()
        db.session.commit()

    @staticmethod
    def read(challenge):
        """
        Access the data of a Docker challenge in a format processable by the front end.
        """
        challenge = DockerChallenge.query.filter_by(id=challenge.id).first()
        data = {
            'id': challenge.id,
            'name': challenge.name,
            'value': challenge.value,
            'docker_image': challenge.docker_image,
            'description': challenge.description,
            'category': challenge.category,
            'state': challenge.state,
            'max_attempts': challenge.max_attempts,
            'type': challenge.type,
            'type_data': {
                'id': DockerChallengeType.id,
                'name': DockerChallengeType.name,
            }
        }
        return data

    @staticmethod
    def create(request):
        """
        Process the challenge creation request.
        """
        data = request.form or request.get_json()
        challenge = DockerChallenge(**data)
        db.session.add(challenge)
        db.session.commit()
        return challenge

    @staticmethod
    def attempt(challenge, request):
        """
        Check whether a given input is correct for a Docker challenge.
        """
        data = request.form or request.get_json()
        input_data = data.get('input')
        expected_output = challenge.value  # Assuming challenge.value holds the expected output
        if input_data == expected_output:
            return True
        else:
            return False

    @staticmethod
    def solve(user, team, challenge, request):
        """
        Insert Solves into the database to mark a Docker challenge as solved.
        """
        solve = Solves(user_id=user.id, team_id=team.id, challenge_id=challenge.id, date=datetime.now())
        db.session.add(solve)
        db.session.commit()


    @staticmethod
    def fail(user, team, challenge, request):
        """
        Insert Fails into the database to mark an incorrect attempt for a Docker challenge.
        """
        fail = Fails(user_id=user.id, team_id=team.id, challenge_id=challenge.id, date=datetime.now())
        db.session.add(fail)
        db.session.commit()

# Add DockerChallengeType to the CHALLENGE_CLASSES dictionary
CHALLENGE_CLASSES['docker'] = DockerChallengeType

class DockerChallenge(Challenges):
    __mapper_args__ = {'polymorphic_identity': 'docker'}
    id = db.Column(None, db.ForeignKey('challenges.id'), primary_key=True)
    docker_image = db.Column(db.String(128), index=True)

# API
from flask_restx import Namespace

container_namespace = Namespace("container", description='Endpoint to interact with containers')

@container_namespace.route("", methods=['POST', 'GET'])
class ContainerAPI(Resource):
    @authed_only
    def post(self):
        """
        Create a new container.
        """
        container_name = request.args.get('name')
        if not container_name:
            return abort(403)

        docker_config = DockerConfig.query.filter_by(id=1).first()
        containers = DockerChallengeTracker.query.all()

        if container_name not in get_repositories(docker_config, tags=True):
            return abort(403)

        client = docker_lib.DockerClient(base_url=docker_config.hostname)

        if is_teams_mode():
            session = get_current_team()
            # First we'll delete all old docker containers (+2 hours)
            for i in containers:
                if int(session.id) == int(i.team_id) and (unix_time(datetime.utcnow()) - int(i.timestamp)) >= 7200:
                    delete_container(client, i.instance_id)
                    DockerChallengeTracker.query.filter_by(instance_id=i.instance_id).delete()
                    db.session.commit()
            check = DockerChallengeTracker.query.filter_by(team_id=session.id).filter_by(docker_image=container_name).first()
        else:
            session = get_current_user()
            for i in containers:
                if int(session.id) == int(i.user_id) and (unix_time(datetime.utcnow()) - int(i.timestamp)) >= 7200:
                    delete_container(client, i.instance_id)
                    DockerChallengeTracker.query.filter_by(instance_id=i.instance_id).delete()
                    db.session.commit()
            check = DockerChallengeTracker.query.filter_by(user_id=session.id).filter_by(docker_image=container_name).first()

        # If this container is already created, we don't need another one.
        if check is not None and not (unix_time(datetime.utcnow()) - int(check.timestamp)) >= 300:
            return abort(403)
        # The exception would be if we are reverting a box. So we'll delete it if it exists and has been around for more than 5 minutes.
        elif check is not None:
            delete_container(client, check.instance_id)
            if is_teams_mode():
                DockerChallengeTracker.query.filter_by(team_id=session.id).filter_by(docker_image=container_name).delete()
            else:
                DockerChallengeTracker.query.filter_by(user_id=session.id).filter_by(docker_image=container_name).delete()
            db.session.commit()

        portsbl = get_unavailable_ports(docker_config)
        create = create_container(client, container_name, session.name, portsbl)
        ports = create.attrs['HostConfig']['PortBindings'].values()

        entry = DockerChallengeTracker(
            team_id=session.id if is_teams_mode() else None,
            user_id=session.id if not is_teams_mode() else None,
            docker_image=container_name,
            timestamp=unix_time(datetime.utcnow()),
            revert_time=unix_time(datetime.utcnow()) + 300,
            instance_id=create.id,
            ports=','.join([p[0]['HostPort'] for p in ports]),
            host=str(docker_config.hostname).split(':')[0]
        )
        db.session.add(entry)
        db.session.commit()
        return "Container created successfully", 200



active_docker_namespace = Namespace("docker", description='Endpoint to retrieve User Docker Image Status')


@active_docker_namespace.route("", methods=['POST', 'GET'])
class DockerStatus(Resource):
    def get(self):
        """
        Get the status of Docker containers.
        """
        docker_config = DockerConfig.query.filter_by(id=1).first()
        client = docker_lib.DockerClient(base_url=docker_config.hostname)

        containers = client.containers.list()

        container_info = []
        for container in containers:
            container_info.append({
                "Container ID": container.id,
                "Name": container.name,
                "Image": container.image.tags[0] if container.image.tags else None,
                "Status": container.status,
                "Ports": container.attrs['NetworkSettings']['Ports'],
                "Created": container.attrs['Created']
            })

        return jsonify(container_info)

docker_namespace = Namespace("docker", description='Endpoint to retrieve dockerstuff')

@docker_namespace.route("", methods=['POST', 'GET'])
class DockerAPI(Resource):
    """
    This is for creating Docker Challenges. The purpose of this API is to populate the Docker Image Select form
    object in the Challenge Creation Screen.
    """

    def get(self):
        docker = DockerConfig.query.filter_by(id=1).first()
        images = get_repositories(docker, tags=True)
        # images = get_repositories(docker, tags=True, repos=docker.repositories)
        if images:
            data = list()
            for i in images:
                data.append({'name': i})
            return {
                'success': True,
                'data': data
            }
        else:
            return {
                       'success': False,
                       'data': [
                           {
                               'name': 'Error in Docker Config!'
                           }
                       ]
                   }, 400




def load(app):
    # Create necessary database tables
    app.db.create_all()

    # Register DockerChallengeType in CHALLENGE_CLASSES dictionary
    CHALLENGE_CLASSES['docker'] = DockerChallengeType

    # Register plugin assets directory
    register_plugin_assets_directory(app, base_path='/plugins/docker_challenges/assets')

    # Define routes for Docker API endpoints
    define_docker_admin(app)
    define_docker_status(app)

    # Add namespaces to CTFd API v1
    CTFd_API_v1.add_namespace(docker_namespace, '/docker')
    CTFd_API_v1.add_namespace(container_namespace, '/container')
    CTFd_API_v1.add_namespace(active_docker_namespace, '/docker_status')
    CTFd_API_v1.add_namespace(kill_container, '/nuke')
