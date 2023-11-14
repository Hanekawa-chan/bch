import threading

from blockchain import BlockChain
from main import validate_task

fake_users = [BlockChain(username='fake_user_1', password='fake_user_1', base_url='https://b1.ahmetshin.com/restapi/'),
              BlockChain(username='fake_user_2', password='fake_user_2', base_url='https://b1.ahmetshin.com/restapi/'),
              BlockChain(username='fake_user_3', password='fake_user_3', base_url='https://b1.ahmetshin.com/restapi/'),
              BlockChain(username='fake_user_4', password='fake_user_4', base_url='https://b1.ahmetshin.com/restapi/'),
              BlockChain(username='fake_user_5', password='fake_user_5', base_url='https://b1.ahmetshin.com/restapi/'),
              BlockChain(username='fake_user_6', password='fake_user_6', base_url='https://b1.ahmetshin.com/restapi/'),
              BlockChain(username='fake_user_7', password='fake_user_7', base_url='https://b1.ahmetshin.com/restapi/'),
              BlockChain(username='fake_user_8', password='fake_user_8', base_url='https://b1.ahmetshin.com/restapi/'),
              BlockChain(username='fake_user_9', password='fake_user_9', base_url='https://b1.ahmetshin.com/restapi/'),
              BlockChain(username='fake_user_10', password='fake_user_10', base_url='https://b1.ahmetshin.com/restapi/')
              ]


def validate_thread(b):
    result = b.get_task().json()
    if len(result['tasks']) > 0:
        print(result)
        for i in result['tasks']:
            id = i['id']
            data_json = i['data_json']
            res = validate_task(id, b, data_json)
            print(res.json())


def loop():
    print('running validators')
    while True:
        for b in fake_users:
            b.register()
            threading.Thread(target=validate_thread, args=[b]).run()


loop()
