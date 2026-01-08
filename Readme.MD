# GQL

This package provides a query library to be used with REST APIs that allows for rich querying capabilities.
It sits on top of standard REST APIs to allow clients to pass complex filters in a standardized way.


## Reason for GQL

Enabling complex querying capabilities over REST APIs can be challenging. GQL addresses this by providing a structured way to define filters, making it easier for clients to interact with RESTful services.

## How it works

This package will have a typescript client, responsible for building the query objects and serializing them into a format that can be sent over REST APIs (e.g., as query parameters or in the request body). On the server side, this package will parse the incoming queries and translate them into appropriate database queries or in-memory filtering logic.

We recommend using the client-side library available at [GQL Client Library](#) TBD

However, if you wish to build your own client, the query structure is as follows:

1. the query keys will be prefixed with `f.` to indicate they are filters. i.e: `f.age`, `f.name`
2. you must provide an operator and a value for each filter. the operator is passed as `f.<field>.o` and the value as `f.<field>.v`.
3. Optionally you can provide a grouping key `f.name.g=1` to group multiple filters together. Filters with the same grouping key will be combined using AND logic, while different grouping keys will be combined using OR logic. filters without a grouping key will be treated as belonging to the default group. 
4. The value will depend on the operator used, but generally it can be:
   - a single value (e.g., string, number, boolean)
   - a list of values (always primitive types)
   - a range, this is a special object with from and to properties. the range is always inclusive on both ends.
  
### Supported Operators

Exact list to be defined

### FC 

Because some proxies can truncate the URL if it is too long, you should provide an `fc` parameter that contains the number of filters included in the request. This helps the server to validate that all filters were received correctly. For example, if you have 3 filters, you would include `fc=3` in your request.
If fc is not provided, the server will make the best effort to parse all filters, but there is a risk of missing some if the URL is truncated silently.


### Usage

This package exports several functionalities:

1. `gql.ParseQuery()`

```go
 http.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
        // Parse query string: /users?name[eq]=john&age[gt]=25&status[in]=active,pending
        query, err := gql.ParseQuery(r.URL.Query())
        if err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        ...
```
Pass the query parameters as an argument and the engine will make its best effort to parse it
(API might change during implementation)

2. `query.ToSql()`

```go
sql, err := query.ToSQLWhere()
sqlAlias, err := query.ToSqlWhereAlias(alias)
```

Once you get the query object, you can retrieve the SQL syntax calling `ToSql`
in case that some keys don't map to the names in your collection, make sure to pass a map 
of strings where the keys can be retrieved

this function will return a section of a sql string

```sql
WHERE ....
```

or an error if it cannot find the key

API might change during implementation
