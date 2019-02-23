#!/usr/bin/env python
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.orm import validates
import json


Base = declarative_base()


# each class is a table
# convention camelcase on class and lowercase underscore on table / column
class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False, index=True)
    picture = Column(String(250))


class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    items = relationship("Item")  # back_populates="category"

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'name': self.name,
            'items': [i.serialize for i in self.items],
        }


class Item(Base):
    # creates the actual table
    __tablename__ = 'item'
    # maps py obj to column & attribute
    id = Column(Integer, primary_key=True)
    # nullable means required to insert
    name = Column(String(80), nullable=False)
    description = Column(String(750), nullable=False)
    # watch_number = Column(Integer, nullable=True)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship('Category')  # back_populates='items'
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @validates('name')
    def validate_name(self, key, name):
        if not name:
            raise AssertionError('Item name is required')
        return name

    @validates('description')
    def validate_description(self, key, description):
        if not description:
            raise AssertionError('Item description is required')
        return description

    @validates('category_id')
    def validate_category_id(self, key, category_id):
        if not category_id:
            raise AssertionError('Item category is required')
        return category_id

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'category_id': self.category_id,
            'name': self.name,
            'id': self.id,  # may not expose
            'description': self.description,
        }


db_connect = json.loads(
    open('/var/www/catalog/client_secrets_db.json',
         'r').read())['db']['connect']
engine = create_engine(db_connect)
Base.metadata.create_all(engine)
