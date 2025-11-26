FROM public.ecr.aws/lambda/python:3.12

# Install runtime and test dependencies
COPY requirements.txt /var/task/requirements.txt
WORKDIR /var/task
RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the project into the image
COPY . /var/task

# Ensure Python can import project modules during pytest
ENV PYTHONPATH=/var/task

# Run the test suite during image build so the build fails on test failure
RUN pytest

CMD ["lambda_function.lambda_handler"]
