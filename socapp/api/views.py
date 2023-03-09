import datetime

import jwt
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import User
from .serializers import UserSerializer


class RegisterView(APIView):
    def post(self, request):
        if 'username' not in request.data:
            return Response({
                'status': 'error',
                'message': 'Username is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        username = request.data['username'].strip()
        if not username:
            return Response({
                'status': 'error',
                'message': 'Username is empty'
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        if 'email' not in request.data:
            return Response({
                'status': 'error',
                'message': 'Email is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        email = request.data['email'].strip()
        if not email:
            return Response({
                'status': 'error',
                'message': 'Email is empty'
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        if 'password' not in request.data:
            return Response({
                'status': 'error',
                'message': 'Password is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        password = str(request.data['password']).strip()
        if not password:
            return Response({
                'status': 'error',
                'message': 'Password is empty'
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        user = User.objects.filter(username=username).first()
        if user:
            return Response({
                'status': 'error',
                'message': 'User with this username already exists.'
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        user = User.objects.filter(email=email).first()
        if user:
            return Response({
                'status': 'error',
                'message': 'User with this email already exists.'
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        serializer = UserSerializer(data=request.data)
        serializer.is_valid()
        serializer.save()

        return Response({
            'status': 'success',
            'message': 'User has been successfully created',
            'data': serializer.data
        })


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
        })
        response.set_cookie(key='jwt', value=token, httponly=True)

        return response


class LogoutView(APIView):
    def post(self, request):
        response = Response({
            'status': 'success',
            'message': 'You have successfully logged out'
        })
        response.delete_cookie('jwt')
        return response


class UserView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            return Response({
                'status': 'error',
                'message': 'You are not logged in'
            }, status=status.HTTP_403_FORBIDDEN)

        try:
            payload = jwt.decode(token, 'socapp', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({
                'status': 'error',
                'message': 'Token has expired, login again'
            }, status=status.HTTP_403_FORBIDDEN)

        user = User.objects.get(id=payload['id'])
        serializer = UserSerializer(user)

        return Response({
            'status': 'success',
            'data': serializer.data
        })
