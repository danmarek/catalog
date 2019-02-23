#!/usr/bin/env python
from flask import (Flask,
                   render_template,
                   url_for,
                   request,
                   flash,
                   redirect,
                   session as login_session,
                   make_response,
                   jsonify)
from model import Item, Category, User, Base
from sqlalchemy.orm import sessionmaker, exc
from sqlalchemy import create_engine, desc, asc
import random
import string
from oauth2client.client import (flow_from_clientsecrets,
                                 FlowExchangeError)
import json
import requests
import logging


# application settings for the catalog
app = Flask(__name__)
# database connection setup
# sqllite
# engine = create_engine('sqlite:///catalog.db')
db_connect = json.loads(
    open('/var/www/catalog/client_secrets_db.json',
         'r').read())['db']['connect']
engine = create_engine(db_connect)
Base.metadata.create_all(engine)
db_session = sessionmaker(bind=engine)
session = db_session()
# import client id secret for google OAuth
CLIENT_ID = json.loads(
    open('/var/www/catalog/client_secrets.json',
         'r').read())['web']['client_id']
APPLICATION_NAME = "catalog"
# Google API Endpoints
_user_info_url = "https://www.googleapis.com/oauth2/v1/userinfo"
_token_info_url = "https://www.googleapis.com/oauth2/v1/tokeninfo"
_revoke_url = "https://accounts.google.com/o/oauth2/revoke"
# logging.basicConfig(filename='catalog.log', level=logging.INFO)
logging.basicConfig(level=logging.INFO)
logging.info('Finished')
print("test this print")
app.secret_key = 'nanonahno'


@app.route('/login')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    # logging.info(login_session)
    # print(login_session)
    return render_template('login.html', STATE=login_session['state'])


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """google connect method

    Connect to google and confirm the one time auth token and setup
    session object for user login session based on google information
    """
    # Validate state token created by the show_login matches the token
    # in the request arguments to confirm no hack
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state value.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        # try use onetime code
        # create onetime code object
        oauth_flow = flow_from_clientsecrets(
            '/var/www/catalog/client_secrets.json', scope='')
        # specify with postmessage this is one time code sending
        oauth_flow.redirect_uri = 'postmessage'
        # initiate exchange and get object back..
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    # and store token
    access_token = credentials.access_token
    # use this token to check valid token
    params = {'access_token': access_token}
    result = requests.get(_token_info_url, params=params)
    # print(result.json())
    # If there was an error in the access token info, abort.
    # if result.get('error') is not None:
    if 'error' in result.json():
        logging.info('Token failed with http 500')
        print('Token failed with http 500')
        response = make_response(json.dumps(result.json()['error']), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    # logging.info('log: google ping response {}'.format(result))
    # print('log: google ping response {}'.format(result))

    # Verify that the access token is used for the intended user.
    # check the id returned by google ping is same as in
    # credentials object for token

    gplus_id = credentials.id_token['sub']
    if result.json()['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    # if ids or client ids do not match then wrong token
    if result.json()['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        logging.info("Token's client ID does not match app's.")
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    # check access token
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    user_info_answer = requests.get(_user_info_url, params=params)
    # logging.info('check log: data google user info response {}'.
    #              format(user_info_answer.json()['picture']))
    # print('check log: data google user info response {}'.
    #              format(user_info_answer.json()['picture']))

    login_session['provider'] = 'google'
    login_session['username'] = user_info_answer.json()['name']
    login_session['picture'] = user_info_answer.json()['picture']
    login_session['email'] = user_info_answer.json()['email']

    # create user if not found in database
    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = 'Welcome'
    flash('Logged in as {}'.format(login_session['username']))
    # logging.info(login_session['user_id'])
    # print(login_session['user_id'])
    return output


# Disconnect based on auth provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        logging.info('logout')
        # logging.info(login_session)
        # print('logout', login_session)
        flash('Successfully logged out.')
        return redirect(url_for('show_catalog'))
    else:
        flash('You were not logged in')
        return redirect(url_for('show_catalog'))


# Disconnect from google OAuth 2.0 to logout
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # revoke and logout
    params = {'token': login_session['access_token']}
    result = requests.get(_revoke_url, params=params)

    # check the result['status'] == '200':
    if result.status_code == requests.codes.ok:
        response = make_response(json.dumps(
            'Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


def create_user(flask_session):
    new_user = User(name=flask_session['username'], email=flask_session[
                   'email'], picture=flask_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=flask_session['email']).one()
    return user.id


def get_user_id(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except exc.NoResultFound:
        return None
    except Exception as e:
        return e


# Section Read / Display the catalog information
# catalog home page
@app.route('/catalog/')
@app.route('/')
def show_catalog():
    page_limit = 10
    categories = session.query(Category).order_by(asc(Category.name)).all()
    items = session.query(Item).order_by(desc(Item.id)).limit(page_limit)
    return render_template('catalog.html', categories=categories, items=items)


# display the category with all items.
@app.route('/catalog/category/<int:category_id>', methods=['GET'])
def show_category(category_id):
    categories = session.query(Category).order_by(asc(Category.name)).all()
    category = session.query(Category).filter_by(
        id=category_id).join(Item).one()
    return render_template('category.html', category=category,
                           items=category.items, categories=categories)


@app.route('/catalog/item/<int:item_id>', methods=['GET'])
def show_item(item_id):
    try:
        item = session.query(Item).filter_by(id=item_id).one()
        return render_template('item.html', item=item)
    except Exception as e:
        flash('Item not found')
        return redirect(url_for('show_catalog'))


# Section Display the catalog in json, you can walk down json
@app.route('/catalog/json')
def show_catalog_json():
    catalog = session.query(Category).join(Item)
    return jsonify(Category=[i.serialize for i in catalog])


@app.route('/catalog/category/<int:category_id>/json')
def show_category_json(category_id):
    catalog = session.query(Category).filter_by(
        id=category_id).join(Item).one()
    return jsonify(Category=[catalog.serialize])


@app.route('/catalog/category/<int:category_id>/items/json')
def show_category_items_json(category_id):
    items = session.query(Item).filter_by(category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/catalog/category/<int:category_id>/item/<int:item_id>/json')
@app.route('/catalog/item/<int:item_id>/json')
def show_item_json(item_id, category_id=None):
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=[item.serialize])


# Section Create, Update Delete the catalog items
# Additional route to autopopulate category when adding items
# from category screen
@app.route('/catalog/category/<int:category_id>/item/add', methods=['GET'])
@app.route('/catalog/item/add', methods=['GET', 'POST'])
def add_item(category_id=None):
    if 'user_id' not in login_session:
        return redirect(url_for('show_login'))

    categories = session.query(Category).order_by(asc(Category.name)).all()
    if request.method == 'POST':
        category_id = request.form['category_id']
        try:
            item = Item(name=request.form['name'],
                        description=request.form['description'],
                        category_id=category_id,
                        user_id=login_session['user_id'])
            session.add(item)
            session.commit()
            flash('New item added')
            return redirect(url_for('show_category', category_id=category_id))
        except AssertionError as e:
            flash('Adding item failed: {}'.format(e))
            return redirect(url_for('show_catalog'))
    else:
        return render_template('additem.html',
                               categories=categories, category_id=category_id)


@app.route('/catalog/item/<int:item_id>/edit', methods=['GET', 'POST'])
def edit_item(item_id):
    if 'user_id' not in login_session:
        return redirect(url_for('show_login'))

    try:
        item = session.query(Item).filter_by(id=item_id).one()
        if item.user_id != login_session['user_id']:
            flash('Users cannot edit other users items.')
            return redirect(url_for('show_catalog'))
    except Exception as e:
        flash('Item not found')
        return redirect(url_for('show_catalog'))

    if request.method == 'POST':
        if request.form['name']:
            item.name = request.form['name']
        if request.form['description']:
            item.description = request.form['description']
        if request.form['category_id']:
            item.category_id = request.form['category_id']
        try:
            session.add(item)
            session.commit()
            flash('Item updated')
            return redirect(url_for('show_item', item_id=item_id))
        except Exception as e:
            flash('Edit item failed: {}'.format(e))
            return redirect(url_for('show_catalog'))
    else:
        categories = session.query(Category).order_by(asc(Category.name)).all()
        return render_template('edititem.html',
                               item=item, categories=categories)


@app.route('/catalog/item/<int:item_id>/delete', methods=['GET', 'POST'])
def delete_item(item_id):
    if 'user_id' not in login_session:
        return redirect(url_for('show_login'))

    item = session.query(Item).filter_by(id=item_id).one()
    if item.user_id != login_session['user_id']:
        flash('Users cannot delete other users items.')
        return redirect(url_for('show_catalog'))

    if request.method == 'POST':
        if 'yes' in request.form:
            session.delete(item)
            session.commit()
            flash('Item deleted')
            return redirect(url_for(
                'show_category', category_id=item.category_id))
        else:
            return redirect(url_for('show_item', item_id=item_id))
    else:
        return render_template('deleteitem.html', item=item)


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=8000, threaded=False)
