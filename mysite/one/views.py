from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render, redirect
from django.urls import reverse
from django.views import generic
from django.utils import timezone
from django.shortcuts import render
from .forms import StudentForm, CourseForm
from .models import Course, Meeting, StudentUser
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required

def welcome(request):
	if request.method == 'POST':
		user = request.user.id
		context = {
			'title': 'Welcome | PILOT Registration'
		}
		return redirect('one:data', context=context)
	else:
		if StudentUser.objects.filter(user=request.user.id).exists():
			return redirect('one:status')
		else:
			return render(request, 'one/welcome.html/')


@login_required
def get_data(request):
	# if this is a POST request we need to process the form data
	if request.method == 'POST':
		# create a form instance and populate it with data from the request:
		form = StudentForm(request.POST)
		user = request.user
		# check whether it's valid:
		if form.is_valid():
			# process the data in form.cleaned_data as required
			student_object, created = StudentUser.objects.get_or_create(user=user)
			student_object.hopid = form.cleaned_data['hopid']
			jhed = form.cleaned_data['jhed']
			student_object.jhed = jhed
			user.email = str(jhed) + '@jhu.edu'
			user.save()
			student_object.grad_year = form.cleaned_data['grad_year']
			student_object.major = form.cleaned_data['major']
			student_object.pre_health = form.cleaned_data['pre_health']
			student_object.save()
			# redirect to a new URL:
			return redirect('one:results', pk=student_object.id)
	# if a GET (or any other method) we'll create a blank form
	else:
		user = request.user
		student_object, created = StudentUser.objects.get_or_create(user=user)
		context = {
			'title': 'Student Information | PILOT Registration',
			'student': student_object
		}
		return render(request, 'one/student_info.html/', context=context)

@login_required
def get_results(request, pk):
	student = StudentUser.objects.filter(id=pk).first()
	# if this is a POST request we need to process the form data
	if request.method == 'POST':
		return redirect('one:detail', pk=student.id)
	# if a GET (or any other method) we'll create a blank form
	else:
		context = {
			'title': 'Your Information | PILOT Registration',
			'student': student
		}
		return render(request, 'one/results.html/', context=context)

@login_required
def details(request, pk):
	student = StudentUser.objects.filter(id=pk).first()
	courses = Course.objects.all()
	enrolled = Meeting.objects.filter(students=student)
	waitlist = Meeting.objects.filter(waitlist=student)

	registered = list(enrolled) + list(waitlist)
	registered_courses = []
	for r in registered:
		registered_courses.append(str(r.course))
	# print(registered_courses)
	context = {
		'title': 'Courses | PILOT Registration',
		'student': student,
		'course_list': courses,
		'registered': registered_courses,
	}
	return render(request, 'one/detail.html/', context=context)

@login_required
def get_courses(request, pk):
	student = StudentUser.objects.filter(id=pk).first()
	course_string = ""
	if request.method == 'POST':
		# create a form instance and populate it with data from the request:
		form = CourseForm(request.POST)
		# check whether it's valid:
		if form.is_valid():
			# process the data in form.cleaned_data as required
			course_list = request.POST.getlist('classes')
			for id in course_list:
				course_string += str(id) + "%"
		# redirect to a new URL:
		return redirect('one:meetings', pk=student.id, course_list=course_string)

@login_required
def get_details(request, pk, course_list):
	student = get_object_or_404(StudentUser, pk=pk)
	course_list = course_list.split('%')
	if request.method == 'POST':
		course_string = ""
		vacant_string = ""
		full_string = ""
		for id in course_list:
			if id != '':
				course_string += str(id) + "%"
				if Meeting.objects.filter(course=get_object_or_404(Course, pk=str(id))).exists():
					data = request.POST[id]
					meeting = get_object_or_404(Meeting, pk=str(data))
					if meeting.enrollment < meeting.max:
						vacant_string += str(data) + "%"
						meeting.students.add(student)
					else:
						full_string += str(data) + "%"
						meeting.waitlist.add(student)
		if full_string == '':
			full_string = "%"
		if vacant_string == '':
			vacant_string = "%"
		return redirect('one:register_results', pk=student.id, course_list=course_string, vacant=vacant_string, full=full_string)
	else:
		object_meetings_dict = {}
		for id in course_list:
			if id != '':
				course = get_object_or_404(Course, pk=id)
				meetings = Meeting.objects.filter(course=course)
				meetings = list(meetings)
				object_meetings_dict[course] = meetings

		context= {
			'title': 'Meeting Times | PILOT Registration',
			'student': student,
			'meetings': object_meetings_dict,
		}
		return render(request, 'one/meetings.html/', context=context)

@login_required
def register_results(request, pk, course_list, vacant, full):
	doubles = []
	if request.method == 'POST':
		return redirect('one:status')
	else:
		student = StudentUser.objects.filter(id=pk).first()
		courses = []
		vacant_meetings = []
		full_meetings = []
		course_list = course_list.split('%')
		vacant = vacant.split('%')
		full = full.split('%')

		for id in course_list:
			if id != '':
				course = get_object_or_404(Course, pk=id)
				courses.append(course)

		for id in vacant:
			if id != '':
				meeting = get_object_or_404(Meeting, pk=id)
				vacant_meetings.append(meeting)

		for id in full:
			if id != '':
				meeting = get_object_or_404(Meeting, pk=id)
				full_meetings.append(meeting)
		context = {
			'title': 'Registration Results | PILOT Registration',
			'student' : student,
			'courses': courses,
			'vacant': vacant_meetings,
			'full': full_meetings,
			'doubles': doubles
		}
		return render(request, 'one/register_results.html/', context=context)

@login_required
def status(request):
	if request.method == 'POST':
		student = get_object_or_404(StudentUser, user=request.user)
		if not StudentUser.objects.filter(user=request.user.id).exists():
			return render(request, 'one/welcome.html/')
		elif not Meeting.objects.filter(students=student).exists() or Meeting.objects.filter(waitlist=student).exists():
			return redirect('one:results', pk=student.id)
	else:
		user = request.user
		student = get_object_or_404(StudentUser, user=user)
		enrolled = list(Meeting.objects.filter(students=student))
		waitlist = list(Meeting.objects.filter(waitlist=student))
		context = {
			'title': 'Your Status | PILOT Registration',
			'student': student,
			'enrolled': enrolled,
			'waitlist': waitlist
		}
		return render(request, 'one/status.html', context=context)

@login_required
def drop(request):
	if request.method == 'POST':
		user = request.user
		student = get_object_or_404(StudentUser, user=user)
		meetings = request.POST.getlist('meeting')
		# drop selected class
		for id in meetings:
			m = Meeting.objects.get(id=int(id))
			m.students.remove(student)
		# return to homepage
		student = get_object_or_404(StudentUser, user=user)
		enrolled = list(Meeting.objects.filter(students=student))
		waitlist = list(Meeting.objects.filter(waitlist=student))
		context = {
			'title': 'Your Status | PILOT Registration',
			'student': student,
			'enrolled': enrolled,
			'waitlist': waitlist
		}
		return render(request, 'one/status.html', context=context)
	else:
		user = request.user
		student = get_object_or_404(StudentUser, user=user)
		enrolled = list(Meeting.objects.filter(students=student))
		waitlist = list(Meeting.objects.filter(waitlist=student))
		context = {
			'title': 'Your Status | PILOT Registration',
			'student': student,
			'enrolled': enrolled,
			'waitlist': waitlist
		}
		return render(request, 'one/drop.html', context=context)
