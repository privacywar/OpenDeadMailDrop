# URLSecurity Module
The URLSecurity module is intended to protect your URL parameters from rewrite and hijacking. It also prevents any and all
SQL injection attempts because your URL parameters are encrypted.

## Sample

### Create The Instance

Using the URLSecurity module is done by create an instance of the SecureParams class. In the following example
we are setting up the redirect to purchase some codes from the DMD service.

        public const string ENTITLEMENT_CODE_PARAM = "FOO1";
        public const string QUANTITY_PARAM = "FOO2";
        public const string AMOUNT_TO_PAY_PARAM = "FOO3";
        
        protected void BuyCodes_Click(object sender, EventArgs e)
        {
            SecureParams p = new SecureParams();
            p[ENTITLEMENT_CODE_PARAM] = EntitlementDO.CODE_ENTITLEMENT;
            p[QUANTITY_PARAM] = NumCodes.SelectedItem.Value;
            decimal cost = GetIAPCost(EntitlementDO.CODE_ENTITLEMENT);
            int qty = int.Parse(NumCodes.SelectedItem.Value);
            p[AMOUNT_TO_PAY_PARAM] = (cost * qty).ToString();
            RedirectTo("SubmitPayment.aspx", p);
        }

Here we are creating a new instance of the SecureParams class.

            SecureParams p = new SecureParams();

Next we are setting up some values that we need for the payment page.

            p[ENTITLEMENT_CODE_PARAM] = EntitlementDO.CODE_ENTITLEMENT;
            p[QUANTITY_PARAM] = NumCodes.SelectedItem.Value;

Finally, we use the nifty helper method to redirect to the payment page. That method is described in the next subsection.

            RedirectTo("SubmitPayment.aspx", p);

### Protecting The Instance
Now we need to show you how to save the SecureParams instance and utilize the super secret record ID
of the instance. See the following method.

        protected void RedirectTo(string page, SecureParams sp)
        {
            int id = sp.SaveToDB();
            SecureParams np = new SecureParams(id);
            Response.Redirect(page + "?params=" + np.Encrypt(), true);
        }

You would place this snippet of code in a class that extends Page (in ASP.NET). How this works is thus:

            int id = sp.SaveToDB();

First we save the current set of URL parameters. This gives us the record ID.

            SecureParams np = new SecureParams(id);

Now we make a new set of SecureParams with the record ID. That will be the only parameter in the URL. This makes the
URL redirection double secure. Not only do you never share the URL parameters with the end user, but you are also
encrypting the URL so that they can't play with the URL id. 

            Response.Redirect(page + "?params=" + np.Encrypt(), true);

Here we tell the page engine to send the location header to the client. 

### Decoding The Params
Once we land back on our commerce page, how do we get those secret parameters?

        protected SecureParams _RequestParams;
        protected void ReadParams()
        {
            string pm = Request["params"];
            SecureParams sp = SecureParams.FromDB(pm);
            _RequestParams = sp;
        }

You would call this method from your Page_Load override. What is this method doing? Lots of magic:

            string pm = Request["params"];

Ugly hard coded name for the parameter. You would use something smarter.

            SecureParams sp = SecureParams.FromDB(pm);

Magic. We just read in the values using the encoded ID in the parameters to the page. That takes care of the
DB plumbing and such. 

            _RequestParams = sp;

That's the final step where we keep the parameters in memory. Now you can access the parameters to the page
and know that your downstream user has not compromised their security. The in-core security is another problem
to solve. You can figure that out.
