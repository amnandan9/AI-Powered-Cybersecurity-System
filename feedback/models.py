from django.db import models
from django.conf import settings
from django.utils import timezone

class Feedback(models.Model):
    RATING_CHOICES = [
        (1, '⭐'),
        (2, '⭐⭐'),
        (3, '⭐⭐⭐'),
        (4, '⭐⭐⭐⭐'),
        (5, '⭐⭐⭐⭐⭐'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='feedback')
    title = models.CharField(max_length=200)
    content = models.TextField()
    rating = models.IntegerField(choices=RATING_CHOICES, default=5)
    created_at = models.DateTimeField(default=timezone.now)
    is_public = models.BooleanField(default=True)
    likes = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='liked_feedback', blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Feedback'
        verbose_name_plural = 'Feedback'

    def __str__(self):
        return f"{self.user.username}'s feedback - {self.title}"

    def get_rating_stars(self):
        return '⭐' * self.rating

    def get_likes_count(self):
        return self.likes.count()
