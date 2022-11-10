from django.db import models

# Create your models here.
class fileupload(models.Model):
    file=models.FileField()

class imageupload(models.Model):
    files=models.ImageField(null=True,blank=True,upload_to="images/")
    key=models.CharField(max_length=30)
    
