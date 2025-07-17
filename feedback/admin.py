from django.contrib import admin
from .models import Feedback

@admin.register(Feedback)
class FeedbackAdmin(admin.ModelAdmin):
    list_display = ('title', 'user', 'rating', 'created_at', 'is_public', 'get_likes_count')
    list_filter = ('rating', 'is_public', 'created_at')
    search_fields = ('title', 'content', 'user__username')
    date_hierarchy = 'created_at'
    actions = ['make_public', 'make_private', 'delete_selected']

    def get_likes_count(self, obj):
        return obj.likes.count()
    get_likes_count.short_description = 'Likes'

    def make_public(self, request, queryset):
        queryset.update(is_public=True)
    make_public.short_description = "Mark selected feedback as public"

    def make_private(self, request, queryset):
        queryset.update(is_public=False)
    make_private.short_description = "Mark selected feedback as private"

    def delete_selected(self, request, queryset):
        queryset.delete()
    delete_selected.short_description = "Delete selected feedback"
