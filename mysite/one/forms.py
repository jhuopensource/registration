from django.forms import ModelForm
from one.models import StudentUser, Course, StudentForm, CourseForm

from django import forms

GRAD_YEAR_CHOICES = [('2020', '2020'), ('2021', '2021'), ('2022', '2022'), ('2023', '2023'), ('2024', '2024')]

MAJOR_CHOICES = [('Undecided','Undecided'), ('Africana Studies','Africana Studies'), ('Anthropology','Anthropology'), ('Applied Mathematics & Statistics','Applied Mathematics & Statistics'), ('Archaeology', 'Archaeology'), ('Behavioral Biology','Behavioral Biology'), ('Biology','Biology'), ('Biomedical Engineering','Biomedical Engineering'), ('Biophysics','Biophysics'), ('Chemical & Biomolecular Engineering','Chemical & Biomolecular Engineering'), ('Chemistry','Chemistry'), ('Civil Engineering','Civil Engineering'), ('Classics', 'Classics'), ('Cognitive Science', 'Cognitive Science'), ('Computer Engineering', 'Computer Engineering'), ('Computer Science','Computer Science'), ('Earth & Planetary Sciences','Earth & Planetary Sciences'), ('East Asian Studies','East Asian Studies'), ('Economics','Economics'), ('Electrical Engineering','Electrical Engineering'), ('Engineering Mechanics','Engineering Mechanics'), ('English','English'), ('Environmental Engineering','Environmental Engineering'), ('Environmental Science', 'Environmental Science'), ('Film & Media Studies','Film & Media Studies'), ('French','French'), ('General Engineering','General Engineering'), ('German','German'), ('History','History'), ('History of Art','History of Art'), ('History of Science, Medicine & Technology','History of Science, Medicine & Technology'), ('Interdisciplinary Studies','Interdisciplinary Studies'), ('International Studies','International Studies'), ('Italian','Italian'), ('Materials Science & Engineering','Materials Science & Engineering'), ('Mathematics','Mathematics'), ('Mechanical Engineering','Mechanical Engineering'), ('Medicine, Science & the Humanities','Medicine, Science & the Humanities'), ('Molecular & Cellular Biology','Molecular & Cellular Biology'), ('Natural Sciences','Natural Sciences'), ('Near Eastern Studies','Near Eastern Studies'), ('Neuroscience','Neuroscience'), ('Philosophy','Philosophy'), ('Physics','Physics'), ('Political Science','Political Science'), ('Psychology','Psychology'), ('Public Health Studies','Public Health Studies'), ('Romance Languages','Romance Languages'), ('Sociology','Sociology'), ('Spanish','Spanish'), ('Writing Seminars','Writing Seminars')]

COURSE_LIST = []
for course in Course.objects.all():
    t = (course.__str__(), course.code)
    COURSE_LIST.append(t)

CHOICES = [
	(True, 'Yes'), (False, 'No')
]

class StudentForm(forms.Form):
	hopid = forms.CharField(required=True, widget=forms.TextInput)
	jhed = forms.CharField(required=True, widget=forms.TextInput)
	major = forms.ChoiceField(required=True, widget=forms.Select, choices=MAJOR_CHOICES)
	grad_year = forms.ChoiceField(required=True, widget=forms.Select, choices=GRAD_YEAR_CHOICES)
	pre_health = forms.ChoiceField(required=True, widget=forms.Select, choices=CHOICES)
	#TODO: add 'is valid' function

class CourseForm(forms.Form):
	classes = forms.ModelMultipleChoiceField(required=True, widget=forms.CheckboxSelectMultiple, queryset= Course.objects.all(), to_field_name="id" )



