Steps for Deloyment:

Step - 1: Install npm packages using 'npm install' and then build using 'npm run build'

Step - 2: Create python virtual environment using 'python -m venv <virtual_environment_name>'

Step - 3: Install dependencies from djngo-backend using 'pip install - requirements.txt'

Step - 4: # Terminal 1 - Celery Worker
celery -A AIToolSuite_prod worker --pool=solo -l info

# Terminal 2 - Celery Beat (for scheduled tasks)
celery -A AIToolSuite_prod beat --loglevel=info