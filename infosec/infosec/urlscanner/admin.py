from django.contrib import admin
from .models import fileupload,imageupload

admin.site.register(fileupload)

# Register your models here.
admin.site.register(imageupload)
