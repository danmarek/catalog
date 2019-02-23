from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
# format of database and objects
from model import Category, Item, Base, User
import datetime
import json

db_connect = json.loads(
    open('/var/www/catalog/client_secrets_db.json',
         'r').read())['db']['connect']

engine = create_engine(db_connect, echo=False)
Base.metadata.bind = engine

db_session = sessionmaker(bind=engine)
session = db_session()

categories = ['ABC', 'NBC', 'CBS']

user = {
    'name': 'Robin Williams',
    'email': 'robin@nanonahno.com',
    'picture': 'https://en.wikipedia.org/wiki/File'
               ':Robin_Williams_Happy_Feet_premiere.jpg'
}

items = {
    'ABC':
        {
            'name': 'The Bachelor',
            'description': '''Colton Underwood, a former
             professional football player who burst onto
             the scene during Season 14 of The Bachelorette,
             comes back to Bachelor Nation looking for a
             teammate who will join him for a life full
             of adventure, philanthropy and lasting love.''',
            'category_id': 1,
            'user_id': 1
        },
    'NBC':
        {
            'name': 'This Is Us',
            'description': '''Jack and his wife - who is
             very pregnant with triplets - have just
             moved into their new home in Pittsburgh.
             Successful and handsome television actor
             Kevin is growing increasingly bored with his
             bachelor lifestyle.''',
            'category_id': 2,
            'user_id': 1
        },
    'CBS':
        {
            'name': 'The Big Bang Theory',
            'description': '''Mensa-fied best friends and roommates
             Leonard and Sheldon, physicists who work at the
             California Institute of Technology, may be able to tell
             everybody more than they want to know about quantum
             physics, but getting through most basic social
             situations, especially ones involving women, totally
             baffles them. How lucky, then, that babe-alicious
             waitress/aspiring actress Penny moves in next door.''',
            'category_id': 3,
            'user_id': 1
        }
}

query_user = session.query(User).filter_by(name=user['name']).first()
if not query_user:
    session.add(User(name=user['name'], email=user['email'],
                     picture=user['picture']))
    session.commit()
    print('{} found for user create {}'.format(query_user, user['name']))
else:
    print('user {} already found'.format(user['name']))


for category in categories:
    query_category = session.query(Category).filter_by(name=category).first()
    if not query_category:
        session.add(Category(name=category))
        session.commit()
        print('{} found for category create {}'.
              format(query_category, category))
        q_item = session.query(Item).\
            filter_by(name=items[category]['name']).first()
        if not q_item:
            session.add(Item(name=items[category]['name'],
                             description=items[category]['description'],
                             category_id=items[category]['category_id'],
                             user_id=items[category]['user_id']))
            session.commit()
            print('{} found for item create {}'.
                  format(q_item, items[category]['name']))
    else:
        print('category {} already found'.format(category))
        print('item {} already found'.format(items[category]['name']))


# used this for test data -> time_stamp_string
def time_stamp():
    return datetime.datetime.now().strftime("%y-%m-%d%H:%M:%S")
