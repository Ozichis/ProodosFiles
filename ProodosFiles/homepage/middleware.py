class TrackLastThreeURLsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get the last three URLs from the session
        last_three_urls = request.session.get('last_three_urls', [])

        # Add the current URL to the list
        current_url = request.path
        if current_url not in last_three_urls:
            last_three_urls.append(current_url)

        # Keep only the last three URLs
        if len(last_three_urls) > 3:
            last_three_urls.pop(0)

        # Save the updated list back to the session
        request.session['last_three_urls'] = last_three_urls

        response = self.get_response(request)
        return response