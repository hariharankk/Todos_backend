import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import datetime
from flask import Flask, render_template,request,jsonify
import sys
import logging
import random
from functools import wraps
import uuid
import string
import jwt
from flask_cors import CORS, cross_origin
from flask_socketio import SocketIO, emit
import time
import threading


class Config(object):  
    DEBUG = False
    TESTING = False
    CSRF_ENABLED = True
    SECRET_KEY = 'this-really-needs-to-be-changed'

class ProductionConfig(Config):
    DEBUG = False


class StagingConfig(Config):
    DEVELOPMENT = True
    DEBUG = True


class DevelopmentConfig(Config):
    DEVELOPMENT = True
    DEBUG = True


class TestingConfig(Config):
    TESTING = True


app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

app.config.from_object(Config)
db_path = os.path.join(os.path.dirname(__file__), 'app2.db')
db_uri = 'sqlite:///{}'.format(db_path)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
db = SQLAlchemy(app)
db.init_app(app)
socketio = SocketIO(app,cors_allowed_origins='*')
message_thread = threading.Event()
thread3 = None
thread_lock = threading.Lock()


@socketio.on('connect')
def test_connect():
    """event listener when client connects to the server"""
    app.logger.info("client has connected")
    emit("connect",{"data":"id: is connected"})

@socketio.on('disconnect')
def disconnect():
    app.logger.info("client has diconnected")
    emit(
        'user disconnected',{"data":"id: is disconnected"},  
        broadcast=True)



class Group_Member_Association(db.Model):
    __tablename__ = "association_table"
    group_id = db.Column(db.ForeignKey("groups.group_key", ondelete="CASCADE"), primary_key=True)
    user_id = db.Column(db.ForeignKey("User.username", ondelete="CASCADE"), primary_key=True)
    role = db.Column(db.String(50),default='நிர்வாகம்')
    group = db.relationship("Group", backref=db.backref("members",cascade="save-update, merge, ""delete, delete-orphan",passive_deletes=True))
    user = db.relationship("User", backref=db.backref("groups",cascade="save-update, merge, ""delete, delete-orphan",passive_deletes=True))

      


user_assigned_to_subtask_table = db.Table(
    'user_assigned_to_subtask',
    db.Model.metadata,
    db.Column('user_id', db.Integer(),
              db.ForeignKey('User.username', ondelete='CASCADE'),
              primary_key=True
              ),
    db.Column('subtask_id', db.String(),
              db.ForeignKey('subtasks.subtask_key', ondelete='CASCADE'),
              primary_key=True
              ),
)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'logged out'})
  
        try:
            # decoding the payload to fetch the stored details
          data = jwt.decode(token, app.config['SECRET_KEY'])
          current_user = User.query\
                .filter_by(username = data['public_id'])\
                .first()
        except:
            return jsonify({
               'message' : 'logged out'})
        # returns the current logged in users contex to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated


class User(db.Model):
    __tablename__ = "User"
    username = db.Column(db.String(80),primary_key=True, unique=True)
    email = db.Column(db.String(80), unique=True)
    password_hash = db.Column(db.String(128))
    admin=db.Column(db.Boolean, default=False, server_default="false")
    phonenumber=db.Column(db.String(80), unique=True)
    #employees = relationship('Employees',backref="User", lazy=True)
    #store = relationship('Store',backref="User", lazy=True)


    @property
    def password(self):
        raise AttributeError('password is not a readable property')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def validate_email(email):
        if User.query.filter_by(email = email).first() is not None:
            return False
        else:
            return True
    
    @staticmethod
    def validate_user_name(username):
        if User.query.filter_by(username = username).first() is not None:
            return False
        else:
            return True

    @staticmethod
    def validate_phonenumber(phonenumber):
        if User.query.filter_by(phonenumber = phonenumber).first() is not None:
            return False
        else:
            return True
        

    def __repr__(self):
        return '<User {}>'.format(self.email)  


    def serialize_public(self):
        return {
            'username': self.username,
            'emailaddress': self.email,
            'phonenumber': self.phonenumber,  
        }

    def get_groups(self):
        groups = []
        roles = {}
        print(self.groups)
        for group in self.groups:
            roles[group.group.name]=group.role
            groups.append(Group.serialize(group.group))
        return groups,roles

    def has_groups(self):
        if len(self.get_groups()) > 0:
            return True
        return False

class Message(db.Model):
    __tablename__ = 'message'
    message = db.Column(db.String(), nullable=False)
    sender = db.Column(db.String(), nullable=False)
    time_created = db.Column(db.DateTime(
        timezone=False), server_default=db.func.now())
    subtask_key = db.Column(db.String(),
                         db.ForeignKey('subtasks.subtask_key', ondelete="CASCADE"))
    message_key = db.Column(db.String(), unique=True,primary_key=True)

    def __init__(self, message, sender, subtask_key, message_key):
        self.message = message
        self.subtask_key = subtask_key
        self.sender = sender
        self.message_key = message_key

    def serialize(self):
        return {
            'subtaskKey': self.subtask_key,
            'message': self.message,
            'sender': self.sender,
            'messageKey': self.message_key,
            'time_created': self.time_created.isoformat(),
        }


class Task(db.Model):
    __tablename__ = 'tasks'

    title = db.Column(db.String(), nullable=False)
    completed = db.Column(db.Boolean(), default=False)
    priority = db.Column(db.Integer(), default=1)
    time_created = db.Column(db.DateTime(
        timezone=False), server_default=db.func.now())
    time_updated = db.Column(db.DateTime(
        timezone=False), onupdate=db.func.now())
    group_key = db.Column(db.String(),
                         db.ForeignKey('groups.group_key', ondelete="CASCADE"))
    task_key = db.Column(db.String(), unique=True,primary_key=True)

    def __init__(self, title, group_key, task_key):
        self.title = title
        self.task_key = task_key
        self.group_key = group_key

    def serialize(self):
        if self.time_updated is None:
            time_updated = self.time_created.isoformat()
        else:
            time_updated = self.time_updated.isoformat()
        return {
            'title': self.title,
            'group_key': self.group_key,
            'priority': self.priority,
            'completed': self.completed,
            'task_key': self.task_key,
            'time_created': self.time_created.isoformat(),
            'time_updated': time_updated,
        }


class SubTask(db.Model):
    __tablename__ = 'subtasks'
    task_key = db.Column(db.String(),
                        db.ForeignKey('tasks.task_key', ondelete="CASCADE"))
    subtask_key = db.Column(db.String(), unique=True, primary_key=True)
    title = db.Column(db.String(), nullable=False)
    completed = db.Column(db.Boolean(), default=False)
    note = db.Column(db.String(), default="")
    due_date = db.Column(db.DateTime(timezone=False))
    priority = db.Column(db.Integer(), default=1)
    reminders = db.Column(db.String())
    time_created = db.Column(db.DateTime(
        timezone=False), server_default=db.func.now())
    time_updated = db.Column(db.DateTime(
        timezone=False), onupdate=db.func.now())
    assigned_to_user = db.relationship("User",
                                       secondary=user_assigned_to_subtask_table,
                                       backref="subtask")

    def __init__(self, title, task_key, subtask_key):
        self.title = title
        self.task_key = task_key
        self.subtask_key = subtask_key

    def serialize(self):
        if self.time_updated is None:
            time_updated = self.time_created.isoformat()
        else:
            time_updated = self.time_updated.isoformat()
        return {
            'task_key': self.task_key,
            'subtask_key': self.subtask_key,
            'title': self.title,
            'completed': self.completed,
            'note': self.note,
            'priority': self.priority,
            'due_date': datetime.date.today().isoformat() if self.due_date is None else self.due_date.isoformat(),
            'reminders': self.reminders,
            'time_created': self.time_created.isoformat(),
            'time_updated': time_updated,
            'message_count': self.get_messagae_count(), 
        }

    def get_messagae_count(self):
      messages = Message.query.filter_by(subtask_key=self.subtask_key).count()
      if messages:
        return int(messages)



    def get_users_assigned_to(self):
        assigned_to = []
        for user in self.assigned_to_user:
            assigned_to.append(User.serialize_public(user))
        return assigned_to


class Group(db.Model):
    __tablename__ = 'groups'

    name = db.Column(db.String())
    group_key = db.Column(db.String(), unique=True, primary_key=True)
    is_public = db.Column(db.Boolean(), default=True)
    time_created = db.Column(db.DateTime(
        timezone=False), server_default=db.func.now())
    time_updated = db.Column(db.DateTime(
        timezone=False), onupdate=db.func.now())


    def __init__(self, name, group_key, is_public):
        self.name = name
        self.group_key = group_key
        self.is_public = is_public

    def serialize(self):
        if self.time_updated is None:
            time_updated = self.time_created.isoformat()
        else:
            time_updated = self.time_updated.isoformat()
        return {
            'name': self.name,
            'members': self.get_members(),
            'group_key': self.group_key,
            'is_public': self.is_public,
            'time_created': self.time_created.isoformat(),
            'time_updated': time_updated,
        }

    def get_members(self):
        members = []
        for member in self.members:
            role = member.role
            print(member.user)
            data=User.serialize_public(member.user)
            data['role']=role
            members.append(data)
        return members

    def is_empty(self):
        if len(self.get_members()) == 0:
            return True
        return False    


@app.route('/api/login', methods=['POST'])
def login():
    user = User.query.filter_by(email=request.json['emailaddress']).first()
    if user is not None and user.check_password(request.json['password']):         
                token = jwt.encode({
                    'public_id': user.username,
                 }, app.config['SECRET_KEY'])
                #app.logger.info('login sucessful')
                return jsonify({'status':True,'token': token.decode('UTF-8'),'data':User.serialize_public(user)})
    else:  
              #app.logger.error('email method user name already exists')
              print('hari')
              return jsonify({'status':False})
        #except:
            #app.logger.error('Login function exception triggered')
         #   return jsonify({'status':False})

def generate_key():
    return ''.join(random.choice(string.ascii_letters + string.digits)  for _ in range(50))

@app.route('/api/register', methods=['POST'])
def register():
    
    #try:
      if request.method == 'POST':
        value_email = User.validate_email(request.json['emailaddress'])
        random_string = request.json['username']
        value_phonenumber = User.validate_phonenumber(request.json['phonenumber'])
        value_user = User.validate_user_name(random_string)
        if value_email and value_phonenumber and value_user:
            new_user = User(
                email = request.json['emailaddress'],
                password = request.json['password'],
               username =  random_string,
               #admin = parse(request.json['admin']),
               phonenumber = request.json['phonenumber']
               )
            token = jwt.encode({
                    'public_id': random_string,
                }, app.config['SECRET_KEY'])

            db.session.add(new_user)
            db.session.commit()
            #app.logger.info
            print('registration success')
            return jsonify({'status':True,'token' : token.decode('UTF-8'),'data':User.serialize_public(new_user)})
        else:
          #app.logger.error
          print('registration data already exists')
          return jsonify({'status':False})
      else:
        #app.logger.error
        print('registration wrong request')
        return jsonify({'status':False})
    #except:
      #app.logger.error('registration function exception triggered')
     # return jsonify({'status':False})



@app.route('/api/group', methods=['GET'])  
@token_required   # Generate new api key
def get_groups(user):
     result = []
     roles={}
     user = User.query.filter_by(username=request.args.get('username')).first()
     if user:
        result,roles = user.get_groups()
        return {"status": 'success', 'data': result,'roles':roles}, 200
     else:
      return {"status": "No api key!"}, 401   

@app.route('/api/group-add', methods=['POST'])
@token_required
def add_groups(user):
       json_data = request.get_json(force=True)
       user = User.query.filter_by(username=json_data['username']).first()
       if user:
          group_key = generate_key()
          group = Group.query.filter_by(group_key=group_key).first()
          while group:
              group_key = generate_key()
              group = Group.query.filter_by(group_key=group_key).first()

          group = Group(name=json_data['name'],
                        group_key=group_key,
                        is_public=json_data['is_public'])
          role=Group_Member_Association(group=group,role=json_data['role'])
          with db.session.no_autoflush:
            user.groups.append(role)  
          db.session.add(group)
          db.session.commit()
          result = Group.serialize(group)
          return {"status": 'success', 'data': result}, 200
       else:
          return {"status": "No user with that api key"}, 404
 
@app.route('/api/group-update', methods=['PATCH'])
@token_required
def group_update(user):
      json_data = request.get_json(force=True)
      group = Group.query.filter_by(group_key=json_data['group_key']).first()
      if group:
        if (group.name != json_data['name']):
           group.name = json_data['name']
        if (group.is_public != json_data['is_public']):
           group.is_public = json_data['is_public']
        db.session.commit()
        return {"status": 'success'}, 200
      else:
        return {"status": "No Group with that group key"}, 404

@app.route('/api/group-delete', methods=['DELETE'])
@token_required
def group_delete(user):
      group = Group.query.filter_by(group_key = request.args.get('group_key')).first()
      if group:
         db.session.delete(group)
         db.session.commit()
         return {"status": 'success'}, 200
      else:
         return {"status": 'Group Not Found'}, 404


@app.route('/api/groupmember-add', methods=['POST'])
@token_required
def add_groupmember(user):
        json_data = request.get_json(force=True)
        group = Group.query.filter_by(group_key = json_data['groupKey']).first()
        if group:
            if group.is_public:
                user = User.query.filter_by(username=json_data['username']).first()
                if user:
                  for m in group.members:
                            if user.username == m.user.username:
                                result = User.serialize_public(user) 
                                return {"status": "User is already added",'data': result}, 200
                  role=Group_Member_Association(user=user,role=json_data['role'])
                  with db.session.no_autoflush:
                    group.members.append(role)
                  db.session.commit()
                  return {"status": 'success'}, 200
                else:
                   return { "status": 'No user found by that username'}, 404
            else:
                return {"status": 'Group is not public'}, 403
        else:
          return {"status": "No Group Found with that group key"}, 404

@app.route('/api/groupmember-get', methods=['GET'])
@token_required
def get_groupmember(user):
       result = []
       group = Group.query.filter_by(group_key=request.args.get('groupKey')).first()
       if group:
         result = group.get_members()
         return {"status": 'success', 'data': result}, 200
       else:
         return {"status": "Group Not Found"}, 404

@app.route('/api/groupmember-update', methods=['PATCH'])
@token_required
def update_groupmember(user):
    json_data = request.get_json(force=True)
    username = json_data['username']
    group = Group.query.filter_by(group_key=json_data['groupKey']).first()
    if group:
      for m in group.members:
        if m.user.username == username:
            with db.session.no_autoflush:
              m.role= json_data['role']
              db.session.commit() 
              return {"status": 'success'}, 200
      return {"status": "Member Not Found in Group"}, 404
    else:
      return {"status": "Group Not Found"}, 405    


@app.route('/api/groupmember-delete', methods=['DELETE'])
@token_required
def delete_groupmember(user):
    username = request.args.get('username')
    group = Group.query.filter_by(group_key=request.args.get('groupKey')).first()
    if group:
      for m in group.members:
        if m.user.username == username:
            with db.session.no_autoflush:
              group.members.remove(m)
            db.session.commit()  
            if group.is_empty():
              db.session.delete(group)
              db.session.commit()
            return {"status": 'success'}, 200
      return {"status": "Member Not Found in Group"}, 404
    else:
      return {"status": "Group Not Found"}, 405    


@app.route('/api/search', methods=['POST'])
@token_required
def search(user):
   result = []
   json_data = request.get_json(force=True)
   print(json_data['search_term'])
   filtered_list = User.query.filter(
            User.username.startswith(json_data['search_term'])).all()
   print(filtered_list)
   for user in filtered_list:
       result.append(User.serialize_public(user))
   return {"status": 'success', 'data': result}, 200

@app.route('/api/assignedtouserhURL-get', methods=['GET'])
@token_required
def assignedtouserhURL_get(user):
       result = []
       subtask = SubTask.query.filter_by(subtask_key=request.args.get('subtask_key')).first()
       if subtask:
            result = subtask.get_users_assigned_to()
            return {"status": 'success', 'data': result}, 200
       else:
            return {"status": "Subtask Not Found"}, 404

@app.route('/api/assignedtouserhURL-add', methods=['POST'])
@token_required
def assignedtouserhURL_add(user):
            json_data = request.get_json(force=True)
            username = json_data['username']
            subtask = SubTask.query.filter_by(subtask_key=json_data['subtask_key']).first()
            if subtask:
                user = User.query.filter_by(
                    username=username).first()
                if user:
                    # Check each member the subtask is assigned to, if a match with the provided username, then remove assignment
                    for m in subtask.assigned_to_user:
                        if user.username == m.username:
                            return {"status": "User is already assigned to Task"}, 201
                    subtask.assigned_to_user.append(user)
                    db.session.commit()
                    return {"status": 'success'}, 201
                else:
                    return {"status": "No user found by that username"}, 404
            else:
                return {"status": "Subtask Not Found"}, 404





@app.route('/api/assignedtouserhURL-delete', methods=['DELETE'])
@token_required
def assignedtouserhURL_delete(user):
      username = request.args.get('username')
      subtask = SubTask.query.filter_by(subtask_key=request.args.get('subtask_key')).first()
      if subtask:
        for m in subtask.assigned_to_user:
          if m.username == username:
            subtask.assigned_to_user.remove(m)
            db.session.commit()
            return {"status": 'success'}, 200
        return {"status": "Subtask not assigned to User"}, 404
      else:
        return {"status": "Subtask Not Found"}, 404    

@app.route('/api/tasks-add', methods=['POST'])
@token_required
def tasks_add(user):
    json_data = request.get_json(force=True)
    task_key = generate_key()
    task = Task.query.filter_by(task_key=task_key).first()
    while task:
          task_key = generate_key()
          task = Task.query.filter_by(task_key=task_key).first()

    task = Task(
            title=json_data['title'],
            group_key=json_data['group_key'],
            task_key=task_key,
            )
    db.session.add(task)
    db.session.commit()
    return {"status": 'success'}, 201

    # List Task //Change to List GROUP TASK, NO NESTED FOR LOOP
@app.route('/api/tasks-get', methods=['GET'])
@token_required
def tasks_get(user):
   result = []
   tasks = Task.query.filter_by(group_key=request.args.get('group_key')).all()
   for task in tasks:
       result.append(Task.serialize(task))
   return {"status": 'success', 'data': result}, 200

    # Update Task
@app.route('/api/tasks-update', methods=['PATCH'])
@token_required
def tasks_update(user):
        json_data = request.get_json(force=True)
        task = Task.query.filter_by(task_key=json_data['task_key']).first()
        if task:
          if (task.completed != json_data['completed']):
              task.completed = json_data['completed']
          if(task.priority != json_data['priority']):
              task.priority = json_data['priority']                        
          db.session.commit()
          result = Task.serialize(task)
          return {"status": 'success', 'data': result}, 200
        else:
          return {"status": "No Task with that task key"}, 404

    # Delete Task
@app.route('/api/tasks-delete', methods=['DELETE'])
@token_required
def tasks_delete(user):
        task = Task.query.filter_by(task_key=request.args.get('task_key')).first()
        if task:
              db.session.delete(task)
              db.session.commit()
              return {"status": 'success'}, 200
        else:
              return {"status": 'No Task found with that task key'}, 404


@app.route('/api/subtasks-add', methods=['POST'])
@token_required
def sub_task_add(user):
            json_data = request.get_json(force=True)
            subtask_key = generate_key()
            subtask = SubTask.query.filter_by(subtask_key=subtask_key).first()
            while subtask:
               subtask_key = generate_key()
               subtask = SubTask.query.filter_by(subtask_key=subtask_key).first()
            subtask = SubTask(
                    title=json_data['title'],
                    task_key=json_data['taskKey'],
                    subtask_key=subtask_key,)
            db.session.add(subtask)
            db.session.commit()
            return {"status": 'success'}, 201

    # List Subtasks
@app.route('/api/subtasks-get', methods=['GET'])
@token_required
def sub_task_get (user):
         result = []
         subtasks = SubTask.query.filter_by(task_key=request.args.get('taskKey')).all()
         for subtask in subtasks:
           result.append(SubTask.serialize(subtask))
         return {"status": 'success', 'data': result}, 200

@app.route('/api/subtasks-update', methods=['PATCH'])
@token_required
def sub_task_update (user):
   json_data = request.get_json(force=True)
   subtask = SubTask.query.filter_by(subtask_key=json_data['subtask_key']).first()
   if subtask:
       if (subtask.note != json_data['note']):
          subtask.note = json_data['note']
       if (subtask.completed != json_data['completed']):
          subtask.completed = json_data['completed']
       if (subtask.priority != json_data['priority']):
          subtask.priority = json_data['priority']   
       if (subtask.due_date != datetime.datetime.fromisoformat(json_data['due_date'])):
          subtask.due_date = datetime.datetime.fromisoformat(json_data['due_date'])
       db.session.commit()
       return {"status": 'success'}, 200
   else:
      return { "status": 'No Subtask found with that subtask key'}, 404


@app.route('/api/subtasks-delete', methods=['DELETE'])
@token_required
def sub_task_delete (user):
    subtask = SubTask.query.filter_by(subtask_key=request.args.get('subtask_key')).first()
    if subtask:
      db.session.delete(subtask)
      db.session.commit()
      return {"status": 'success'}, 200
    else:
      return { "status": 'No Subtask found with that subtask key'}, 404

@app.route('/api/message_send', methods=['POST'])
@token_required
def send_message(user):
    json_data = request.get_json(force=True)
    message_key = generate_key()
    message = Message.query.filter_by(message_key=message_key).first()
    while message:
          message_key = generate_key()
          message = Message.query.filter_by(message_key=message_key).first()

    message = Message(
            message = json_data['message'],
            sender = json_data['sender'],
            subtask_key = json_data['subtaskKey'],
            message_key = message_key,
            )
    db.session.add(message)
    db.session.commit()
    return {"status": 'success'}, 201

 

@app.route('/api/message-get', methods=['GET'])
@token_required
def message_get (user):
         result = []
         messages = Message.query.filter_by(subtask_key=request.args.get('subtask_key')).order_by(Message.time_created.desc()).all()
         if messages:
            for message in messages:
               result.append(Message.serialize(message))
            return {"status": 'success', 'data': result}, 200
         else:
           return {"status": 'failure', 'data': result}, 200
 
@socketio.on('/message/stop_thread', namespace="/message-disconnect")
def message_threads():
    print("your message thread is stopped")
    if message_thread.is_set():
        print("message_thread")
        global thread3
        message_thread.clear()
        with thread_lock:
          if thread3 is not None:
              thread3 = None
    else:
        print('Your message thread is not locked')

def backgroundhistory_thread(id):
  while message_thread.is_set():  
    try:
         result = []
         messages = Message.query.filter_by(subtask_key=id).order_by(Message.time_created.desc()).all()
         if messages:
            for message in messages:
               result.append(Message.serialize(message))
            print(result)   
            emit("/message/get",{"data" :result})
         else:
            print('no messages')
            emit("/message/get",{"data" :[]})
    except:
      print('exception triggered');
      emit("/message/get",{"data" :[]})
    finally:
        time.sleep(3)  

    
  

@socketio.on('/message/get', namespace="/message-get")
def message_getdata(id):
  print('connected')
  print('received message: ' + str(id))  
  global thread3
  with thread_lock:
    if thread3 is None:
        message_thread.set()
        thread3 = socketio.start_background_task(backgroundhistory_thread(id))
  emit("/message/get",{"data" :[]})



if __name__ == "__main__":
    with app.app_context():
      db.create_all()    
    app.run() # or setting host to '0.0.0.0'
