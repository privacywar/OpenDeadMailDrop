create table [dbo].[url_params]
(
[id] [int] IDENTITY(1,1) NOT NULL,
[params] [varchar] (1024) NOT NULL,
[expiration] [smalldatetime] NOT NULL,
 CONSTRAINT [PK_url_params_id] PRIMARY KEY NONCLUSTERED 
(
	[id] ASC
)
)
ON [PRIMARY]
go
