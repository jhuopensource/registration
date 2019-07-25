import datetime

from django.db import models
from django.utils import timezone
from django.forms import ModelForm

DAYS = [('Monday', 'MON'),
        ('Tuesday','TUES'),
        ('Wednesday','WED'),
        ('Thursday','THURS'),
        ('Friday','FRI'),
        ('Saturday','SAT'),
        ('Sunday','SUN')]

GRAD_YEAR_CHOICES = ['2020', '2021', '2022', '2023', '2024']

MAJOR_CHOICES = ['Undecided', 'Africana Studies', 'Anthropology', 'Applied Mathematics & Statistics','Archaeology','Behavioral Biology','Biology','Biomedical Engineering','Biophysics','Chemical & Biomolecular Engineering','Chemistry','Civil Engineering','Classics','Cognitive Science','Computer Engineering','Computer Science','Earth & Planetary Sciences','East Asian Studies','Economics','Electrical Engineering','Engineering Mechanics','English','Environmental Engineering','Environmental Science','Environmental Studies','Film & Media Studies','French','General Engineering','German','History','History of Art','History of Science, Medicine & Technology','Interdisciplinary Studies','International Studies','Italian','Materials Science & Engineering','Mathematics','Mechanical Engineering','Medicine, Science & the Humanities','Molecular & Cellular Biology','Natural Sciences','Near Eastern Studies','Neuroscience','Philosophy','Physics','Political Science','Psychology','Public Health Studies','Romance Languages','Sociology','Spanish','Writing Seminars']

class Student(models.Model):
	hopid = models.CharField(max_length=200)
	jhed = models.CharField(max_length=200)
	major = models.CharField(max_length=100)
	grad_year = models.CharField(max_length=4)
	pre_health = models.BooleanField(default=False)

	def __str__(self):
		return self.jhed

class StudentForm(ModelForm):
	class Meta:
		model = Student
		fields = ['hopid', 'jhed', 'major', 'grad_year', 'pre_health']


class Course(models.Model):
	name = models.CharField(max_length=200)
	prof = models.CharField(max_length=200)
	code = models.CharField(max_length=200, default='0')

	def __str__(self):
		return self.name + ' with Professor ' + self.prof

class CourseForm(ModelForm):
	class Meta:
		model = Course
		fields = ['name', 'code']

class Meeting(models.Model):
	course = models.ForeignKey(Course, on_delete=models.CASCADE)
	start_time = models.CharField(max_length=15)
	end_time = models.CharField(max_length=15)
	day = models.CharField(max_length=10, choices=DAYS)
	max = models.IntegerField(default=15)
	enrollment = models.IntegerField(default=0)
	waitlist = models.ManyToManyField(Student, blank=True, related_name="meeting_waitlist")
	students = models.ManyToManyField(Student, blank=True, related_name="meeting_students")

	def __str__(self):
		return "Day: %s, Time: %s - %s" % (self.day, self.start_time, self.end_time)


class Question(models.Model):
	question_text = models.CharField(max_length=200)
	pub_date = models.DateTimeField('date published')

	def was_published_recently(self):
		now = timezone.now()
		return now - datetime.timedelta(days=1) <= self.pub_date <= now

	def __str__(self):
		return self.question_text


class Choice(models.Model):
	question = models.ForeignKey(Question, on_delete=models.CASCADE)
	choice_text = models.CharField(max_length=200)
	votes = models.IntegerField(default=0)

	def __str__(self):
		return self.choice_text
