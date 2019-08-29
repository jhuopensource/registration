from django.urls import path
from users import views as user_views
from django.contrib.auth import views as auth_views
from . import views

app_name = 'one'
urlpatterns = [
	path('', views.welcome, name='home'),
	path('status/', views.status, name='status'),
	path('drop/', views.drop, name='drop'),
	path('signin/', user_views.create_user, name='sign_in'),
	path('login/', auth_views.LoginView.as_view(template_name='users/login.html'), name='login'),
	path('logout/', auth_views.LogoutView.as_view(template_name='users/logout.html'), name='logout'),
	path('get_data/', views.get_data, name='data'),
	path('<int:pk>/results/', views.get_results, name='results'),
	path('<int:pk>/details/', views.details, name='detail'),
	path('<int:pk>/details/get_courses/', views.get_courses, name='courses'),
	path('<int:pk>/meetings/<str:course_list>/get_details/', views.get_details , name='meetings'),
	path('<int:pk>/meetings/<str:course_list>/<str:vacant>/<str:full>/register/', views.register_results , name='register_results'),
]
