from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.db.models import Count
from datetime import datetime, timedelta
from .models import Feedback
from .forms import FeedbackForm

def is_staff(user):
    return user.is_staff

# Create your views here.

@login_required
def feedback_list(request):
    # Get filter parameters
    time_filter = request.GET.get('time_filter', 'all')
    rating_filter = request.GET.get('rating', None)
    sort_by = request.GET.get('sort', 'likes')  # Default sort by likes
    
    # Base queryset with likes count annotation
    feedbacks = Feedback.objects.filter(is_public=True).annotate(likes_count=Count('likes'))
    
    # Apply time filter
    if time_filter == 'week':
        feedbacks = feedbacks.filter(created_at__gte=datetime.now() - timedelta(days=7))
    elif time_filter == 'month':
        feedbacks = feedbacks.filter(created_at__gte=datetime.now() - timedelta(days=30))
    
    # Apply rating filter
    if rating_filter:
        feedbacks = feedbacks.filter(rating=rating_filter)
    
    # Apply sorting
    if sort_by == 'likes':
        feedbacks = feedbacks.order_by('-likes_count', '-created_at')
    else:
        feedbacks = feedbacks.order_by('-created_at')
    
    # Pagination - 5 items per page
    paginator = Paginator(feedbacks, 5)  # Show 5 feedbacks per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    form = FeedbackForm()
    return render(request, 'feedback/feedback_list.html', {
        'page_obj': page_obj,
        'form': form,
        'time_filter': time_filter,
        'rating_filter': rating_filter,
        'sort_by': sort_by,
    })

@login_required
def submit_feedback(request):
    if request.method == 'POST':
        form = FeedbackForm(request.POST)
        if form.is_valid():
            feedback = form.save(commit=False)
            feedback.user = request.user
            feedback.save()
            messages.success(request, 'Thank you for your feedback!')
            return redirect('feedback:list')
    return redirect('feedback:list')

@login_required
def like_feedback(request, feedback_id):
    feedback = get_object_or_404(Feedback, id=feedback_id)
    if request.user in feedback.likes.all():
        feedback.likes.remove(request.user)
        liked = False
    else:
        feedback.likes.add(request.user)
        liked = True
    return JsonResponse({
        'liked': liked,
        'likes_count': feedback.get_likes_count()
    })

@login_required
@user_passes_test(is_staff)
def delete_feedback(request, feedback_id):
    feedback = get_object_or_404(Feedback, id=feedback_id)
    feedback.delete()
    messages.success(request, 'Feedback deleted successfully.')
    return redirect('feedback:list')
