from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

file_routes = Blueprint('file_routes', __name__)

