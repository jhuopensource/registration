

from django.contrib import admin
from django.db import models
from django import forms
from .models import StudentUser, Course, Meeting, ActivateSite
admin.site.register(StudentUser)
admin.site.register(Course)
admin.site.register(ActivateSite)

class StudentsInline(admin.StackedInline):
	model = Meeting.students.through
	verbose_name = "Enrolled Student"
	verbose_name_plural = "Enrolled Students"
	inline_actions = ['delete_selected']

class WaitlistInline(admin.StackedInline):
	model = Meeting.waitlist.through
	verbose_name = "Waitlisted Student"
	verbose_name_plural = "Waitlisted Students"
	inline_actions = ['delete_selected']

class MeetingAdmin(admin.ModelAdmin):
	inlines = [
		StudentsInline,
		WaitlistInline,
	]
	exclude = ('students', 'waitlist',)
	list_display = (Meeting, 'course')
	#formfield_overrides = {
	#	models.ManyToManyField: {'widget': forms.CheckboxSelectMultiple},
	#}

admin.site.register(Meeting, MeetingAdmin)
