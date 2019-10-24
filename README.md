# instagram-scraper
Instagram posts and user metadata scraping

## Usage

- Install dependencies using the requirements.txt file
- Install MongoDB to store results
- Provide your account credentials in JSON format:
    ```
    {
    		"email" : "",
    		"username" : "",
    		"password" : ""
    }
    ```
- Scraper allows to scrape from a username (`--u`) or from a hashtag (`--t`). In both cases, the number of posts to scrape needs to be set (`--N`).
