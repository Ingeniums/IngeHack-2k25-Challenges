from django.urls import path
from .views import quote_list, add_quote

urlpatterns = [
    path('', quote_list, name='quote_list'),  
    path('add/', add_quote, name='add_quote'),  
]