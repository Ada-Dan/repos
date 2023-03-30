## Capstone Project Part I: Define Your Product
Project: Accommodation Booking App Using the MERN Stack.

### Software Requirements

### System Architecture Considerations

This is a list of the system requirements I have taken into account while planning and creating an accommodation booking app using the MERN stack and deploying it on Heroku.

**Operating System:**

All commonly used operating systems support the MERN stack. Windows, Linux, and macOS are typical choices that are compatible with the tools I plan to use for development and deployment.

**Node.js and NPM:**

Will be used to build and run the app. I have selected these tools because Node.js is a popular server-side JavaScript runtime environment that allows me to build scalable and efficient web applications, while NPM is the package manager for Node.js that allows me to manage the dependencies of my project

**MongoDB:**

The app will utilse a MongoDB database to store user and accommodation data. I chose MongoDB because it is a NoSQL document-oriented database that stores data in a JSON-like format, making it scalable, flexible, and allowing me to store and access data quickly.

**Express.js:**

Is a backend framework for Node.js. I chose Express.js because it provides a robust set of features for building web applications, it provides an easy-to-use API for building RESTful APIs.

**React.js:**

Is a front-end library for building user interfaces. I chose React.js because it is fast, efficient, a provides a powerful set of tools for building a dynamic and responsive UI. 

**CSS and SCSS:**

I will be using CSS and SCSS to style the application.
I chose to use these styling languages because they are the standard for styling on the web, and SCSS is a preprocessor that extends the functionality of CSS, allowing me to create an attractive and responsive user interface.

**Heroku:**

I will use an Heroku account to deploy my application. I chose to use Heroku because it is a cloud platform that allows me to deploy and run my application on the cloud, provides an easy-to-use interface for deploying my app, and supports a wide range of languages and frameworks, including the MERN stack.

**Git:**

I will use Git to manage version control and deploy my code to Heroku. I chose Git because it is a popular version control system that allows me to manage changes to my codebase, track changes to my code, and deploy my code to Heroku.

**Package.json:**

Used to manage dependencies and scripts. I chose to use a package.json file because it allows me to easily manage the libraries and frameworks my project depends on and provides a simple way to run scripts such as build, test, and deploy.

**APIs:**

Additional integretion of third-party APIs such as Cloudinary which will be used to handle image uploads of accommodation.

**JWT (JSON Web Token):** 

I will be using JWT to secure my application. I chose to use JWT because it provides a secure way to transmit information between client and server, and it allows me to verify the authenticity of a user and their session.

#### System Requirements

Overview:

The accommodation booking application is a web-based platform that allows users to search for, book and manage their accommodation reservations. It also allows hosts to upload and manage accomodation. There will also be an admin dashboard that allows for the management of users and accomodation. The application will be developed using the MERN stack, and it will be deployed on Heroku.

**Functionality:**

The application will have the following features:

**User registration and login:**

Users will be able to create an account and login to the application to access its features.

**Search functionality:**

Users will be able to search for accommodations by specifying the location, check-in and check-out dates, and the number of guests.

**Reservation**

From the list of available rooms the user will be able to reserve a selection of rooms. This selection will update the the current list of avaiable rooms. 

**Accommodation listings:** 

The application will display a list of accommodations that match the user's search criteria, with details such as the price, location, description, and photos.

**Booking functionality:**

Users will be able to book accommodation by selecting from a list of available rooms. 

**User Roles:**

The application will have two main user roles: guests and hosts, hosts will have admin access. Guests will be the ones who will search for and reserve accommodation, while hosts will be the ones who list their accommodations for booking, upload images and view and manage users.

**Popular Accommodation Booking Platforms**

Some of the top accommodation booking apps currently in the market are Airbnb, Booking.com and Expedia. 
To differentiate this app from these competitors, a focus on offering a simpler and more user-friendly interface, or improving certain functionality such as the search and booking process could be implimented in the design. Alternatively, the app could target a specific niche or market segment, such as luxury or eco-friendly accommodations.

#### User Stories 
**Person 1:**

**Use Case: Search for Accommodation**

**Brief Description:**

Person 1, a guest, wants to find accommodation in London for their upcoming trip. They log into the app, search for available accommodations in London, and filters their search by price and location. They find a suitable option and reserves it.

**Person 2:**

**Use Case: List Accommodation**

**Brief Description:**

Brief Description: Person 2, a host, wants to list their apartment on the app. They log into the app, provides details such as the apartment's location, number of rooms, description, and photos. The system approves the listing and makes it available for guests to book.

**Person 3**

**Use Case: View and Manage Bookings**

**Brief Description:** 

The admin wants to view and manage all the accommodations and users on the app. They log into the admin dashboard, where they can see all the the accommodations and users. The admin has access to CRUD operations on users and accommodations.

## Author

Richard Bewley 2023