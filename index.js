const express = require('express');
const app = express()
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config()
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)
const port = process.env.PORT || 5000

// middleware
app.use(cors())
app.use(express.json())


const { MongoClient, ServerApiVersion, ObjectId, Int32 } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.jtchhsy.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();


    const reviewCollection = client.db("ShopwiseDB").collection("review");
    const userCollection = client.db("ShopwiseDB").collection("users");
    const shopCollection = client.db("ShopwiseDB").collection("shops");
    const productCollection = client.db("ShopwiseDB").collection("products");
    const cartCollection = client.db("ShopwiseDB").collection("carts");
    const paymentCollection = client.db("ShopwiseDB").collection("payments");

    // middleware
const verifyToken = (req, res, next)=>{
    console.log('inside verify token',req.headers.authorization);
    if(!req.headers.authorization){
      return res.status(401).send({message: 'unauthorized access'})
    }
    const token = req.headers.authorization.split(' ')[1]
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded)=> {
      if(err){
        return res.status(401).send({message: 'unauthorized access'})
      }
      req.decoded = decoded
      next()
    });
  }

  // use verify manager after verifytoken
const verifyManager  = async(req, res, next)=>{
  const email = req.decoded.email;
  const query = {email: email}
  const user = await userCollection.findOne(query)
  const ismanager = user?.role === 'manager'
  if(!ismanager){
    return res.status(403).send({message: "forbidden access"})
  }
  next()
}
  // use verify admin after verifytoken
const verifyAdmin  = async(req, res, next)=>{
  const email = req.decoded.email;
  const query = {email: email}
  const user = await userCollection.findOne(query)
  const isadmin = user?.role === 'admin'
  if(!isadmin){
    return res.status(403).send({message: "forbidden access"})
  }
  next()
}

    // jwt api
    app.post('/jwt', async(req, res)=>{
        const user = req.body
        const token =  jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
          expiresIn: '1h'
        })
        res.send({token})
      })

    //site data api
    app.get('/reviews', async(req, res)=>{
        const result =await reviewCollection.find().toArray()
        res.send(result)
    })
    app.post('/shops',verifyToken, async(req, res)=>{
        const shop = req.body  
      const result = await shopCollection.insertOne(shop)
        res.send(result)
    })
    app.get('/shops/:email',verifyToken,verifyManager, async(req, res)=>{
      const email=req.params.email;
      const query = {email: email}
      const result = await shopCollection.findOne(query)
      res.send(result)
  })
  app.get('/shops',verifyToken,verifyAdmin, async(req, res)=>{
    const result =await shopCollection.find().toArray()
    res.send(result)
  })
  app.post('/products',verifyToken,verifyManager, async(req, res)=>{
    const product = req.body  
    const result = await productCollection.insertOne(product)
    res.send(result)
  })
  app.get('/products/:email',verifyToken, verifyManager, async(req, res)=>{
      const email=req.params.email;
      const filter = {email: email}
      const result = await productCollection.find(filter).toArray()
      res.send(result)
  })
  app.get('/products',verifyToken,verifyAdmin, async(req, res)=>{
      
      const result = await productCollection.find().toArray()
      res.send(result)
  })
  app.patch('/products/:id',verifyToken,verifyManager,  async(req, res)=>{
    const product = req.body
    const id = req.params.id
    const filter= {_id: new ObjectId(id)}
    const updatedProduct = {
      $set:{
        productName: product.productName,
          img: product.img,
          quantity: product.quantity,
          location: product.location,
          productionCost: product.productionCost,
          profit: product.profit,
          description: product.description,
          discount: product.discount,
          listPrice: product.listPrice,
          sellingPrice: product.sellingPrice,
      }
    }
    const result = await productCollection.updateOne(filter, updatedProduct)
    res.send(result)
  })
  app.delete('/products/:id',verifyToken,verifyManager,  async(req, res)=>{
    const id = req.params.id;
    const query = {_id: new ObjectId(id)}
    const result = await productCollection.deleteOne(query);
    res.send(result)
  } )
  app.post('/carts',verifyToken,verifyManager, async(req, res)=>{
      const cartItem = req.body
        const result = await cartCollection.insertOne(cartItem)
        res.send(result)
  })
  app.get('/carts/:email',verifyToken, verifyManager, async(req, res)=>{
    const email=req.params.email;
    const filter = {email: email}
    const result = await cartCollection.find(filter).toArray()
    res.send(result)
})
  app.delete('/carts/:id',verifyToken, verifyManager, async(req, res)=>{
    const id = req.params.id
    const query = {_id: new ObjectId(id)}
      const result = await cartCollection.deleteOne(query)
      res.send(result)
  })

  // payment
  app.post("/create-payment-intent", verifyToken, verifyManager, async (req, res) => {
    const { price } = req.body;
    const amount = parseInt(price * 100);
    console.log('bill', amount);

    // Create a PaymentIntent with the order amount and currency
    const paymentIntent = await stripe.paymentIntents.create({
      amount: amount,
      currency: "BDT",
      payment_method_types: [
        "card"
      ],
    });
  
    res.send({
      clientSecret: paymentIntent.client_secret,
    });
  })
  app.post('/payments/subscription', verifyToken, verifyManager, async(req, res)=>{
    const item = req.body
    const payment = {
      email: item.email,
      price: item.price,
      limit:item.limit,
      shopName:item.shopName,
      status: item.status,
    };
    const paymentResult = await paymentCollection.insertOne(payment)
    console.log('payment info', payment);

    const shopResult = await shopCollection.updateOne(
      { shopName: payment.shopName },
      {
        $inc: { limit: payment.limit }, 
        
      }
    );
    res.send(paymentResult, shopResult)
  })
  app.post('/payments', verifyToken, verifyManager, async(req, res)=>{
    const item = req.body
    const payment = {
      email: item.email,
      price: item.price,
      transcationId: item.transcationId,
      date: item.date,
      timecount: new Int32(item.timecount),
      cartIds: item.cartIds,
      productIds: item.productIds?.map(id=> new ObjectId(id)),
      status: item.status,
    };
    const paymentResult = await paymentCollection.insertOne(payment)
    console.log('payment info', payment);

    // delete each item form the cart
    const query = {_id: {
      $in: payment.cartIds.map(id=> new ObjectId(id))
    }}
    const deleteResult = await cartCollection.deleteMany(query)
    
    // Update sale count & quantity in productCollection
    for (const productId of payment.productIds) {
      await productCollection.updateOne(
        { _id: productId },
        {
          $inc: { saleCount: 1, quantity: -1 }, // Increment the sale count by 1
          
        }
      );
    }
    res.send({paymentResult, deleteResult})

  })

  app.get('/payments/:email',verifyToken,verifyManager, async(req, res)=>{
    const query = {email: req.params.email}
    const result = await paymentCollection.aggregate([
      {
        $match: query
      },
      {
        $unwind: '$productIds'
      },
      {
        $lookup: {
          from: 'products',
          localField:'productIds',
          foreignField: '_id',
          as: 'productlists'
        }
      },
      {
        $unwind: '$productlists'
      }, 
    ]).sort({timecount:-1}).toArray()
    res.send(result)
  })

    // user api
    app.get('/users/:email',verifyToken, async(req, res)=>{
        const email=req.params.email;
        const query = {email: email}
        const result = await userCollection.findOne(query)
        res.send(result)
    })
    app.get('/users',verifyToken,verifyAdmin, async(req, res)=>{
  
        const result = await userCollection.find().toArray()
        res.send(result)
    })
    app.get('/users/manager/:email', verifyToken, async(req, res)=>{
      const email = req.params.email;
      if(email !== req.decoded.email){
        return res.status(403).send({message: 'unauthorized access'})
      }
      const query = {email: email}
      const user =await userCollection.findOne(query)
      let manager = false
      if(user){
        manager = user?.role === 'manager'
      }
      res.send({manager})
    })
    app.get('/users/admin/:email', verifyToken, async(req, res)=>{
      const email = req.params.email;
      if(email !== req.decoded.email){
        return res.status(403).send({message: 'unauthorized access'})
      }
      const query = {email: email}
      const user =await userCollection.findOne(query)
      let admin = false
      if(user){
        admin = user?.role === 'admin'
      }
      res.send({admin})
    })
    app.post('/users', async(req, res)=>{
        const user = req.body
        // insert email if user doesn't exists(social login)
        const query = {email: user.email}
        const isExist = await userCollection.findOne(query)
        if(isExist){
            return res.send({message:'user already exists', insertedId: null})
        }
        const result = await userCollection.insertOne(user)
        res.send(result)
    })
    app.patch('/users/manager/:email',verifyToken, async(req, res)=>{
        const item = req.body
        const email = req.params.email
        const filter = {email: email}
        const updatedUser = {
            $set:{
                role: 'manager',
                shopId: item.shopId,
                shopLogo: item.shopLogo,
                shop: item.shop
            }
        }
        const result = await userCollection.updateOne(filter, updatedUser)
        res.send(result)
    })

    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    // console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);


app.get('/', (req, res)=>{
    res.send('Shopwise is booming')
})

app.listen(port, ()=>{
    console.log(`Shopwise is running on port ${port}`);
})