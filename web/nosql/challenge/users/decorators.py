from django.core.cache import cache
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from functools import wraps
import time

def throttle(limit=5, period=60):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            user_ip = request.META.get('REMOTE_ADDR')
            cache_key = f'throttle_{user_ip}'
            requests = cache.get(cache_key, [])
            
            # Clean up old requests
            current_time = time.time()
            requests = [req for req in requests if req > current_time - period]
            
            if len(requests) >= limit:
                return JsonResponse({'error': 'Too many requests'}, status=429)

            requests.append(current_time)
            cache.set(cache_key, requests, timeout=period)
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
