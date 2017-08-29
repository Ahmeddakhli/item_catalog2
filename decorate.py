from functools import wraps
from flask import redirect, url_for, jsonify,\
    session as login_session
from database_setup import Base, Restaurant, MenuItem, User
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Prevent unauthorized users from modification, They must login first
        if 'username' not in login_session:
            return redirect(url_for('/login'))
        return func(*args, **kwargs)
    return wrapper


def category_exist(func):
    @wraps(func)
    def wrapper(restaurant_id):
        # Check if Restaurant doesn't exist in database
        if session.query(Restaurant).filter_by(id=restaurant_id).first() is None:
            return jsonify({'error': 'This Field does not exist!'})
        return func(restaurant_id)
    return wrapper


def item_exist(func):
    @wraps(func)
    def wrapper(restaurant_id, menu_id):
        # Check if MenuItem doesn't exist in database
        if session.query(MenuItem).filter_by(id=menu_id, restaurant_id=restaurant_id)\
                .first() is None:
            return jsonify({'error': 'This MOOC does not exist!'})
        return func(restaurant_id, menu_id)
    return wrapper


# TODO: Add owner_check decorator for catalog and item
