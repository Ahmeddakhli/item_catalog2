from flask import Flask, render_template, request, redirect,\
     jsonify, url_for, flash
from sqlalchemy import create_engine, asc

from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json

from flask import make_response
from decorate import login_required, category_exist, item_exist
import requests

app = Flask(__name__)


APPLICATION_NAME = "Restaurant Menu App"

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

# OAuth APP ID and SECRET for Facebook
APP_ID = '470117420037000'
APP_SECRET = '44104613a669e6bb977752c9fdaebd74'

# Connect to Database and create database session
engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.sample(string.ascii_letters + string.digits, 32))
    login_session['state'] = state

    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += "  style = width: 300px; height: 300px; border-radius: 150px;"\
              " -webkit-border-radius: 150px; -moz-border-radius: 150px;> "
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print("access token received %s " % access_token)
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = "https://graph.facebook.com/oauth/access_token?"\
          "grant_type=fb_exchange_token&client_id=%s&client_secret=%s&"\
          "fb_exchange_token=%s" % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we
        have to split the token first on commas and select the first index
        which gives us the key : value for the server access token then we
        split it on colons to pull out the actual token value and replace the
        remaining quoteswith nothing so that it can be used directly in the
        graph api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = "https://graph.facebook.com/v2.8/me?access_token=%s&"\
          "fields=name,id,email" % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = "https://graph.facebook.com/v2.8/me/picture?access_token=%s&"\
          "redirect=0&height=200&width=200" % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += "  style = width: 300px; height: 300px;border-radius: 150px;"\
              " -webkit-border-radius: 150px;-moz-border-radius: 150px;> "

    flash("Now logged in as %s" % login_session['username'])
    return output
# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(
            json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for givenuser.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbdisconnect/')
def fbdisconnect():
    """Logout from Facebook Auth"""
    facebook_id = login_session.get('facebook_id')

    # The access token must me included to successfully logout
    access_token = login_session.get('access_token')
    if facebook_id is None:
        print('Current user not connected.')
        return jsonify(error={'msg': 'Current user not connected.'}), 401

    url = 'https://graph.facebook.com/{}/permissions?access_token={}'\
        .format(facebook_id, access_token)
    result = requests.delete(url)
    print('result by requests ', result.json())

    del login_session['facebook_id']
    del login_session['access_token']
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['user_id']
    del login_session['provider']
    return jsonify(success={'msg': 'Successfully disconnected.'}), 200


def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).first()
    return user

# To use this function in templates
app.jinja_env.globals['user_info'] = getUserInfo


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).first()
        return user.id
    except:
        return None



# JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()
    itemz = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in itemz])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id=menu_id).first()
    return jsonify(Menu_Item=Menu_Item.serialize)


@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants=[r.serialize for r in restaurants])


# Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
    restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
    if 'username' not in login_session:
        return render_template('publicrestaurants.html',
                               restaurants=restaurants)
    else:
        return render_template('restaurants.html', restaurants=restaurants)


# Create a new restaurant
@app.route('/restaurant/new/', methods=['GET', 'POST'])
@login_required
def newRestaurant():
    if request.method == 'POST':
        Restaurantnew = Restaurant(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(Restaurantnew)
        flash('New Restaurant %s Successfully Created' % Restaurantnew.name)
        session.commit()
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('newRestaurant.html')

# Edit a restaurant


@app.route('/restaurant/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
@category_exist
@login_required
def editRestaurant(restaurant_id):
    Restaurantedited = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if Restaurantedited.user_id != login_session['user_id']:
        return "<script>function myFunction()"\
                 "{alert('You are not authorized to edit this restaurant."\
                 "Please create your own restaurant in order to edit.');}"\
                 "</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            Restaurantedited.name = request.form['name']
            flash('Restaurant Edited %s' % editedRestaurant.name)
            return redirect(url_for('showRestaurants'))
    else:
        return render_template('editRestaurant.html',
                               restaurant=editedRestaurant)


# Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
@category_exist
@login_required
def deleteRestaurant(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurantDelete = session.query(
        Restaurant).filter_by(id=restaurant_id).first()
    if restaurantDelete.user_id != login_session['user_id']:
        return "<script>function myFunction()"\
               "{alert('You are not authorized to delete this restaurant." \
               "Please create your own restaurant in order to delete.');}"\
               "</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(restaurantDelete)
        flash('%s Successfully Deleted' % restaurantDelete.name)
        session.commit()
        return redirect(url_for('showRestaurants',
                                restaurant_id=restaurant_id))
    else:
        return render_template('deleteRestaurant.html',
                               restaurant=restaurantDelete)

# Show a restaurant menu


@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
@category_exist
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()
    creator = getUserInfo(restaurant.user_id)
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    if 'username' not in login_session\
            or creator.id != login_session['user_id']:
        return render_template('publicmenu.html', items=items,
                               restaurant=restaurant, creator=creator)
    else:
        return render_template('menu.html', items=items,
                               restaurant=restaurant, creator=creator)


# Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/',
           methods=['GET', 'POST'])
@category_exist
@login_required
def newMenuItem(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()
    if login_session['user_id'] != restaurant.user_id:
        return "<script>function myFunction()"\
               "{alert('You are not authorized to add menu items to this"\
               "restaurant.Please create your own restaurant in order to"\
               "add items.');}"\
               "</script><body onload='myFunction()''>"
    if request.method == 'POST':
        Itemnew = MenuItem(name=request.form['name'],
                           description=request.form['description'],
                           price=request.form['price'],
                           course=request.form['course'],
                           restaurant_id=restaurant_id,
                           user_id=restaurant.user_id)
        session.add(Itemnew)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (Itemnew.name))
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('newmenuitem.html', restaurant_id=restaurant_id)

# Edit a menu item


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit',
           methods=['GET', 'POST'])
@item_exist
@login_required
def editMenuItem(restaurant_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    Itemedited = session.query(MenuItem).filter_by(id=menu_id).one()
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if login_session['user_id'] != restaurant.user_id:
        return "<script>function myFunction()"\
               "{alert('You are not authorized to edit menu items to this"\
               "restaurant.Please create your own restaurant in order to"\
               "edit items.');}"\
               "</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            Itemedited.name = request.form['name']
        if request.form['description']:
            Itemedited.description = request.form['description']
        if request.form['price']:
            Itemedited.price = request.form['price']
        if request.form['course']:
            Itemedited.course = request.form['course']
        session.add(Itemedited)
        session.commit()
        flash('Menu Item Edited')
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('editmenuitem.html',
                               restaurant_id=restaurant_id, menu_id=menu_id,
                               item=Itemedited)


# Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete',
           methods=['GET', 'POST'])
@item_exist
@login_required
def deleteMenuItem(restaurant_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    itemDelete = session.query(MenuItem).filter_by(id=menu_id).one()
    if login_session['user_id'] != restaurant.user_id:
        return "<script>function myFunction()"\
                "{alert('You are not authorized to delete menu items to this"\
                "restaurant.Please create your own restaurant in order to"\
                "delete items.');}"\
                "</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(itemDelete)
        session.commit()
        flash('Menu Item Deleted')
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('deleteMenuItem.html', item=itemDelete)


@app.route('/disconnect')
def disconnect():
    """Logout from any oauth provider"""
    if 'provider' in login_session:
        if login_session.get('provider') == 'google':
            gdisconnect()
        if login_session.get('provider') == 'facebook':
            fbdisconnect()
        try:
            del login_session['access_token']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            del login_session['user_id']
            del login_session['provider']
        except KeyError:
            pass

        flash("You have successfully been logged out.")
        return redirect(url_for('showRestaurants'))

    flash("You were not logged in!")
    return redirect(url_for('showRestaurants'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
