import json
import time
import uuid

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
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


def ddos_loop():
    while True:
        myuuid = uuid.uuid4()
        b = BlockChain(username=str(myuuid), password=str(myuuid),
                       base_url='https://b1.ahmetshin.com/restapi/')
        b.register()
        time.sleep(0.1)
        data = {
            'type_task': 'send_coins',
            'from_hach': b.hach_user,
            'to_hach': '0973b965a7834d82e8ea50825a54cdeca08fda0911a1c224c06e8d08060ebdb6',
            'count_coins': 100
        }
        time.sleep(1)
        result = b.get_task().json()
        if result['tasks']:
            for i in result['tasks']:
                id = i['id']
                data_json = i['data_json']
                res = validate_task(id, b, data_json)
                if res.json() != True:
                    res = validate_task(id, b, data_json)


# thread_one = threading.Thread(target=loop)
# thread_one.start()
# thread_mine = threading.Thread(target=ddos_loop)
# thread_mine.start()


@app.route('/')
def index():
    name = request.cookies.get('username')
    coins = None
    user_hash = None
    b = bs.get(name)
    if b is not None:
        user_hash = b.hach_user
        coins_json = b.check_coins()
        print(coins_json.json())
        if coins_json.json()['success']:
            coins = coins_json.json()['coins']
        # find_user_blocks(b, user_hash)
    else:
        b = BlockChain(username=request.cookies.get('username'), password=request.cookies.get('password'),
                       base_url='https://b1.ahmetshin.com/restapi/')
        if b is not None:
            bs[name] = b
            user_hash = b.hach_user
            coins_json = b.check_coins()
            print(coins_json.json())
            if coins_json.json()['success']:
                coins = coins_json.json()['coins']
            # find_user_blocks(b, user_hash)
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
    to_hash = request.json['to_hash']
    value = request.json['value']
    b = bs.get(name)
    print(to_hash, value)
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
    b = bs.get(name)
    response = b.get_task()
    print('response', response.json())
    return render_template('tasks.html', error=error, tasks=response.json()['tasks'])


@app.route('/history')
def history():
    error = None
    name = request.cookies.get('username')
    b = bs.get(name)
    blocks = find_user_blocks(b, b.hach_user)
    print('history', blocks)
    return render_template('history.html', error=error, blocks=blocks)


@app.route('/history/global')
def global_history():
    error = None
    name = request.cookies.get('username')
    b = bs.get(name)
    all_blocks = get_blocks(b)
    # blocks = find_user_blocks(b, b.hach_user)
    return render_template('history.html', error=error, blocks=all_blocks)


@app.route('/validate', methods=['POST'])
def validate():
    name = request.cookies.get('username')
    b = bs.get(name)
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
    return result


def find_user_blocks(b, user_hash):
    result = b.get_chains().json()
    blocks = []
    # print(result)
    for block in result['chains']['block_active']:
        if block['data_json']:
            for block_in_blocks in block['data_json']:
                block_data = block_in_blocks['data_json']
                if block_data['type_task'] == 'send_coins':
                    if block_data['from_hach'] == user_hash or block_data['to_hach'] == user_hash:
                        blocks.append(block_data)
    return blocks


def get_blocks(b):
    result = b.get_chains().json()
    blocks = []
    # print(result)
    for block in result['chains']['block_active']:
        if block['data_json']:
            for block_in_blocks in block['data_json']:
                block_data = block_in_blocks['data_json']
                if block_data['type_task'] == 'send_coins':
                    blocks.append(block_data)
    return blocks


def add_friend(b, friend_hash):
    return send_message(b, friend_hash, message='HI')


def send_message(b, friend_hash, message):
    data = {
        'type_task': 'custom',
        'from_hach': b.hach_user,
        'to_hach': friend_hash,
        'message': message
    }
    return b.send_task(data)


@app.route('/friends/add', methods=['POST'])
def add_friend_html():
    if request.method == 'POST':
        name = request.cookies.get('username')
        b = bs.get(name)
        friend_hash = request.json['user_hash']
        add_friend(b, friend_hash)
        return "OK"


@app.route('/friends/list', methods=['GET'])
def friends_list():
    name = request.cookies.get('username')
    b = bs.get(name)
    # friends = get_friends(b)
    friends = [Friend("adachi")]
    print(friends)
    return render_template('friends_list.html', friends=friends)


@app.route('/friends/list/<name>', methods=['GET'])
def messages_list(name):
    username = request.cookies.get('username')
    b = bs.get(username)
    # messages = get_messages(b, name)
    messages = [Message('adachi', "Hi")]
    return render_template('messages_list.html', messages=messages, )


class Friend:
    def __init__(self, hash):
        self.hash = hash
        self.link = "/friends/list/"+hash


class Message:
    def __init__(self, hash, value):
        self.hash = hash
        self.value = value


def get_friends(b):
    result = b.get_chains().json()
    blocks = []
    # print(result)
    for block in result['chains']['block_active']:
        if block['data_json']:
            for block_in_blocks in block['data_json']:
                block_data = block_in_blocks['data_json']
                if block_data['type_task'] == 'custom':
                    if block_data['from_hach'] == b.hach_user or block_data['to_hach'] == b.hach_user:
                        blocks.append(block_data)
    friends = []
    print(blocks)
    for block in blocks:
        if block['from_hach'] == b.hach_user:
            friend = Friend(block['to_hach'])
            friends.append(friend)
        else:
            friend = Friend(block['from_hach'])
            friends.append(friend)
    return friends


def get_messages(b, friend_hash):
    result = b.get_chains().json()
    blocks = []
    # print(result)
    for block in result['chains']['block_active']:
        if block['data_json']:
            for block_in_blocks in block['data_json']:
                block_data = block_in_blocks['data_json']
                if block_data['type_task'] == 'custom':
                    if ((block_data['from_hach'] == b.hach_user or block_data['to_hach'] == b.hach_user) and
                            (block_data['from_hach'] == friend_hash or block_data['to_hach'] == friend_hash)):
                        blocks.append(block_data)
    messages = []
    print(blocks)
    for block in blocks:
        message = Message(block['from_hach'], block["message"])
        messages.append(message)
    return messages
# flask --app main run
