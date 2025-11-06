from django.urls import path
from . import views

urlpatterns = [
    path('', views.home,name='home'),
    path('about/', views.about,name='about'),
    path('contact/', views.contact,name='contact'),
    path('login/', views.login_page, name='login'),
    path('signup/', views.signup_page, name='signup'),
    path('logout/', views.logout_user, name='logout'),
    
    
    path('adminlogin/', views.admin_login, name='adminlogin'),
  
    path('adminlogout/', views.admin_logout, name='adminlogout'),
   


    path('adminpanel/', views.admin_panel, name='adminpanel'),
    path('adminpanel/edit/<int:user_id>/', views.edit_user, name='edit_user'),
    path('adminpanel/delete/<int:user_id>/', views.delete_user, name='delete_user'),
    path('adminpanel/create/', views.create_user, name='create_user'),
    path('adminpanel/block_unblock/<int:user_id>/', views.block_unblock_user, name='block_unblock_user'),


]
