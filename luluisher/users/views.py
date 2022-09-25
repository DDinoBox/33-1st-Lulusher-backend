import json, re, bcrypt
from json import JSONDecodeError

from django.http            import JsonResponse
from django.views           import View
from django.conf            import settings

from users.models import User
from core.utils   import Validation

class SignUpView(View):
    def post(self, request): 
        try: 
            input_data     = json.loads(request.body)
            email          = input_data['email']
            password       = input_data['password']
            
            REX_EMAIL    = '^[a-zA-Z0-9+-_.]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
            REX_PASSWORD = '^(?=.*[a-zA-z])(?=.*[0-9])(?=.*[$`~!@$!%*#^?&\\(\\)\-_=+]).{8,16}$'
            
            if User.objects.filter(email=email).exists():
                return JsonResponse({'Message': 'ERROR_ACCOUNT_ALREADY_EXIST'}, status=400)
            if not re.match(REX_EMAIL, email):
                return JsonResponse({'message' : 'INVALID_EMAIL_--_NEEDS_@_AND_.'}, status=400)
            if not re.match(REX_PASSWORD, password):
                return JsonResponse({'message' : 'INVALID_PASSWORD'}, status=400)
            
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            User.objects.create(
                name            = input_data['name'],
                email           = email,
                password        = hashed_password,
                mobile_number   = input_data['mobile_number'],
                address         = input_data['address'],
                email_subscribe = input_data['email_subscribe']
            ) 
            return JsonResponse({'message' : 'SUCCESS'}, status=201)
        
        except KeyError:
            return JsonResponse({'message' : 'Key_Error'}, status=400)
    
class SignInView(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            user = User.objects.get(email=data['email'])

            if not bcrypt.checkpw(data['password'].encode('utf-8'), user.password.encode('utf-8')):
                return JsonResponse({'message' : 'INVALID_PASSWORD'}, status=401)

            return JsonResponse({
                'message'     : 'SUCCESS',
                'access_token': self.generate_jwt(user),
                'user_id'     : user.id,
                'user_name'   : user.name,
                'user_grade'  : user.grade
            }, status=200)

        except KeyError:
            return JsonResponse({'message' : 'KEY_ERROR'}, status=400)

        except ValueError:
            return JsonResponse({'message' : 'VALUE_ERROR'}, status=400)

        except User.DoesNotExist:
            return JsonResponse({'message' : 'INVALID_ACCOUNT'}, status=404)