import datetime
import jwt
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import User
from .serializers import UserSerializer


class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class LoginView(APIView):
    def post(self, request):
        username = request.data['username']
        password = request.data['password']

        user = User.objects.filter(username=username).first()

        if user is None:
            return Response({
                'status': 'error',
                'message': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)

        if not user.check_password(password):
            return Response({
                'status': 'error',
                'message': 'Incorrect password'
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }
        token = jwt.encode(payload, 'socapp', algorithm='HS256')

        response = Response({
            'status': 'success',
            'message': 'You have successfully logged in',
            'data': {
                'token': token
            }
        }, status=status.HTTP_200_OK)
        response.set_cookie(key='jwt', value=token, httponly=True)

        return response