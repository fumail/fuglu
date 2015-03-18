# -*- coding: utf-8 -*-
#   Copyright 2009-2015 Oli Schacher
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# $Id$
#
"""
Intelligent Greylist Plugin
"""


from fuglu.shared import ScannerPlugin, DUNNO
import fuglu.extensions.sql
import time
import unittest
import re


if fuglu.extensions.sql.ENABLED:
    from sqlalchemy import Table, Column, TEXT, TIMESTAMP, Integer, String, MetaData, ForeignKey, Unicode, Boolean, DateTime, select
    from sqlalchemy.sql import and_
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import mapper, relation, column_property, object_session
    DeclarativeBase = declarative_base()
    metadata = DeclarativeBase.metadata

    greylist_table = Table("greylist", metadata,
                           Column('id', Integer, primary_key=True),
                           Column('created', TIMESTAMP, nullable=False),

                           )

    awl_table = Table("autowhitelist", metadata,
                      Column('id', Integer, primary_key=True),
                      Column('vacation_id', None, ForeignKey('vacation.id')),
                      Column('sent', TIMESTAMP, nullable=False),
                      Column('recipient', Unicode(255), nullable=False),
                      )
    vacation_mapper = mapper(GreylistEntry, greylist_table)
    whitelist_mapper = mapper(WhitelistEntry, awl_table)


class GreylistPlugin(ScannerPlugin):

    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.requiredvars = {
            'dbconnectstring': {
                'default': '....todo',
                'description': 'sqlalchemy connectstring to store the greylist',
                'confidential': True,
            },
        }

        self.logger = self._logger()
        self.cache = None
