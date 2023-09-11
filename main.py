import json
import threading
import time

from blockchain import BlockChain
from flask import Flask, render_template, request, redirect, make_response

link_client = 'https://b1.ahmetshin.com/static/blockchain.py'
bs = {}

app = Flask(__name__)

fake_users = [BlockChain(username='fake_user_1', password='fake_user_1', base_url='https://b1.ahmetshin.com/restapi/'),
              BlockChain(username='fake_user_2', password='fake_user_2', base_url='https://b1.ahmetshin.com/restapi/'),
              BlockChain(username='fake_user_3', password='fake_user_3', base_url='https://b1.ahmetshin.com/restapi/'),
              BlockChain(username='fake_user_4', password='fake_user_4', base_url='https://b1.ahmetshin.com/restapi/'),
              BlockChain(username='fake_user_5', password='fake_user_5', base_url='https://b1.ahmetshin.com/restapi/')]


def loop():
    while True:
        for b in fake_users:
            time.sleep(5)
            result = b.get_task().json()
            if result['tasks']:
                for i in result['tasks']:
                    id = i['id']
                    data_json = i['data_json']
                    validate_task(id, b, data_json)


thread_one = threading.Thread(target=loop)
thread_one.start()


@app.route('/')
def index():
    name = request.cookies.get('username')
    coins = None
    user_hash = None
    b = bs.get(name)
    if b is not None:
        user_hash = b.hach_user
        coins_json = b.check_coins()
        if coins_json.json()['success']:
            coins = coins_json.json()['coins']
    else:
        b = BlockChain(username=request.cookies.get('username'), password=request.cookies.get('password'),
                       base_url='https://b1.ahmetshin.com/restapi/')
        if b is not None:
            bs[name] = b
            user_hash = b.hach_user
            coins_json = b.check_coins()
            if coins_json.json()['success']:
                coins = coins_json.json()['coins']
    return render_template('index.html', name=name, coins=coins, user_hash=user_hash)


def valid_login(username, password):
    b = BlockChain(username=username, password=password, base_url='https://b1.ahmetshin.com/restapi/')
    b.register()
    bs[username] = b
    return b is not None


@app.route('/login', methods=['POST', 'GET'])
def login():
    error = None
    # if request.cookies.get('username') is not None and request.cookies.get('password') is not None:
    #     print(request.cookies.get('username'))
    #     if valid_login(request.cookies.get('username'), request.cookies.get('password')):
    #         return make_response(redirect('/'))
    if request.method == 'POST':
        if valid_login(request.form['username'], request.form['password']):
            response = make_response(redirect('/'))
            response.set_cookie('username', request.form['username'])
            response.set_cookie('password', request.form['password'])
            return response
        else:
            error = 'Invalid username/password'
    return render_template('login.html', error=error)


@app.route('/send', methods=['POST'])
def send():
    error = None
    print(error)
    name = request.cookies.get('username')
    to_hash = request.form['to_hash']
    value = request.form['value']
    b = bs[name]
    data = {
        'type_task': 'send_coins',
        'from_hach': b.hach_user,
        'to_hach': to_hash,
        'count_coins': value
    }
    response = b.send_task(data)
    return response.json()


@app.route('/tasks')
def tasks():
    error = None
    name = request.cookies.get('username')
    b = bs[name]
    response = b.get_task()
    print('response', response.json())
    return render_template('tasks.html', error=error, tasks=response.json()['tasks'])


@app.route('/validate', methods=['POST'])
def validate():
    name = request.cookies.get('username')
    b = bs[name]
    id = request.form['id']
    data_json = request.form['data_json']
    validate_task(id, b, data_json)
    return redirect('/tasks')


def validate_task(id, b, data_json):
    hash = b.get_hash_object(json.dumps(data_json))
    result_hash = b.make_hash(hash)
    data = {
        'type_task': 'BlockTaskUser_Solution',
        'id': id,
        'hash': result_hash
    }

    result = b.send_task(data)
    print(result.json())

# flask --app main run

