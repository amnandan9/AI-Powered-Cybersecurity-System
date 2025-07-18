from django.urls import path
from . import views

app_name = 'feedback'

urlpatterns = [
    path('', views.feedback_list, name='list'),
    path('submit/', views.submit_feedback, name='submit'),
    path('like/<int:feedback_id>/', views.like_feedback, name='like'),
    path('delete/<int:feedback_id>/', views.delete_feedback, name='delete'),
] 