from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Quote
from .forms import QuoteForm
from django.views.decorators.csrf import csrf_exempt

# Display all public quotes and private quotes of the logged-in user
@csrf_exempt
@login_required
def quote_list(request):
    filter_params = request.GET.dict()
    quotes = Quote.objects.filter(**filter_params, private=False) | Quote.objects.filter(author=request.user)
    return render(request, 'quote_list.html', {'quotes': quotes})

# Add a new quote (login required)
@csrf_exempt
@login_required
def add_quote(request):
    if request.method == 'POST':
        form = QuoteForm(request.POST)
        if form.is_valid():
            new_quote = form.save(commit=False)
            new_quote.author = request.user  
            new_quote.save()
            return redirect('quote_list')  
    else:
        form = QuoteForm()
    return render(request, 'add_quote.html', {'form': form})
